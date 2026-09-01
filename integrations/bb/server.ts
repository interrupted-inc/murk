// bb plugin: grant-scoped murk secrets for agent threads.
//
// Agents get two native tools — murk_plan (value-free schema) and murk_get
// (grant-gated reads). Grants are minted by the operator with `bb murk grant
// mint`, which uses murk's own grant machinery: an ephemeral age identity that
// can decrypt exactly the named keys. By default murk_get delivers values as a
// 0600 dotenv file in the thread's worktree and returns only key names + the
// file path; a grant minted with --reveal (and allowed by settings) may return
// its keys' values inline. Everything fails closed: unknown keys, expired
// TTLs, revoked grants, non-local hosts.
import { existsSync, mkdirSync, realpathSync, rmSync } from "node:fs";
import * as path from "node:path";
import type { BbPluginApi } from "@get-bb/plugin-sdk";
import { z } from "zod";
import { withGrantIdentity } from "./lib/binding";
import { KEY_NAME_PATTERN, renderDotenv } from "./lib/dotenv";
import { GRANT_MIGRATIONS, GrantStore, isExpired, type GrantRecord } from "./lib/grants";
import { agentPlan, mintGrant, revokeGrant, runMurk } from "./lib/murk-cli";

/**
 * Per-thread delivery filename. Namespacing by thread id means the plugin
 * never guesses at a user's filename and never collides across threads
 * sharing one worktree/environment.
 */
function deliveryFilename(threadId: string): string {
  return `.murk-${threadId}.env`;
}

const PRIMARY_HOST_TTL_MS = 60_000;

const TOOL_IDS = ["murk_plan", "murk_get"];
const SKILL_IDS = ["murk"];

interface ThreadTarget {
  worktree: string;
  hostId: string;
}

/**
 * Resolve symlinks in a vault path. murk keys its stored-key auto-discovery on
 * the absolute vault path, so /var/folders vs /private/var (macOS) must agree.
 */
function canonicalVault(vaultPath: string): string {
  try {
    return realpathSync(vaultPath);
  } catch {
    return vaultPath;
  }
}

export default async function plugin(bb: BbPluginApi) {
  const settings = bb.settings.define({
    defaultScope: {
      type: "select",
      label: "Default grant scope",
      options: ["project", "thread"],
      default: "project",
    },
    vaultPath: {
      type: "string",
      label: "Vault path override (absolute; blank = <worktree>/.murk)",
      default: "",
    },
    allowRevealGrants: {
      type: "boolean",
      label: "Allow reveal grants (murk_get may return granted values inline)",
      default: true,
    },
  });

  const db = bb.storage.database();
  bb.storage.migrate(db, GRANT_MIGRATIONS);
  const store = new GrantStore(db);

  // Identity key material lives ONLY here, as 0600 files in the plugin's own
  // data directory — never in SQLite, kv, or anything frontend-readable.
  function agentKeysDir(): string {
    const dir = path.join(bb.server.experimental_dataDir, "plugins", bb.pluginId, "agent-keys");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
  }

  async function vaultOverride(): Promise<string | null> {
    const { vaultPath } = await settings.get();
    const trimmed = vaultPath.trim();
    if (!trimmed) return null;
    if (!path.isAbsolute(trimmed)) throw new Error(`the vaultPath setting must be an absolute path, got ${trimmed}`);
    return trimmed;
  }

  // ---- local-host gate -----------------------------------------------------
  // v1 is local-host-only. The documented contract for "the server's own
  // machine" is SystemConfigResponse.primaryHostId (bb.sdk.system.config);
  // bb.sdk.files documents that an omitted hostId targets that same
  // "primary/local host". The gate fails closed: unknown or null primary host
  // withholds the tools, and execute() re-checks asynchronously.
  const gate: { primaryHostId: string | null | undefined; fetchedAt: number } = {
    primaryHostId: undefined,
    fetchedAt: 0,
  };

  async function primaryHostId(): Promise<string | null> {
    const now = Date.now();
    if (gate.primaryHostId !== undefined && now - gate.fetchedAt < PRIMARY_HOST_TTL_MS) {
      return gate.primaryHostId;
    }
    try {
      const config = await bb.sdk.system.config();
      gate.primaryHostId = config.primaryHostId ?? null;
      gate.fetchedAt = now;
    } catch (error) {
      bb.log.warn(`could not resolve the primary host id: ${error instanceof Error ? error.message : String(error)}`);
      return gate.primaryHostId ?? null;
    }
    return gate.primaryHostId;
  }

  bb.agents.configure((context) => {
    const known = gate.primaryHostId !== undefined && gate.primaryHostId !== null;
    if (!known) void primaryHostId(); // warm the cache for the next resolution; withhold now
    const local = known && context.host.id === gate.primaryHostId;
    return local ? { tools: TOOL_IDS, skills: SKILL_IDS } : { tools: [], skills: [] };
  });

  async function requireLocal(hostId: string): Promise<void> {
    const primary = await primaryHostId();
    if (primary === null || hostId !== primary) {
      throw new Error(
        "murk tools are local-host-only in v1: this thread's environment does not run on the bb server's own host",
      );
    }
  }

  // ---- thread → worktree resolution ---------------------------------------
  async function resolveThreadTarget(threadId: string): Promise<ThreadTarget> {
    const thread = await bb.sdk.threads.get({ threadId });
    if (!thread.environmentId) throw new Error("this thread has no environment to deliver secrets into");
    const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
    if (!environment.path) throw new Error("this thread's environment has no workspace path");
    await requireLocal(environment.hostId);
    return { worktree: environment.path, hostId: environment.hostId };
  }

  function toolError(message: string): { content: Array<{ type: "text"; text: string }>; isError: true } {
    return { content: [{ type: "text", text: `murk: ${message}` }], isError: true };
  }

  // ---- key → grant resolution ----------------------------------------------
  /**
   * Map requested keys to covering grants. Every explicitly requested key must
   * be covered by an active grant or the whole call fails closed. When reveal
   * grants are allowed, a covering reveal grant wins for its keys.
   */
  function assignGrants(
    requested: string[],
    grants: GrantRecord[],
    allowReveal: boolean,
  ): Map<string, GrantRecord> {
    const assignment = new Map<string, GrantRecord>();
    for (const key of requested) {
      const covering = grants.filter((grant) => grant.keys.includes(key));
      if (covering.length === 0) {
        throw new Error(
          `${key} is not covered by any active grant for this thread — ` +
            `ask the user to mint one with: bb murk grant mint --keys ${key}`,
        );
      }
      const revealGrant = allowReveal ? covering.find((grant) => grant.reveal) : undefined;
      assignment.set(key, revealGrant ?? covering[0]);
    }
    return assignment;
  }

  /** Decrypt each key with its assigned grant identity. Fails closed per key. */
  function decryptAssigned(assignment: Map<string, GrantRecord>): Map<string, string> {
    const byGrant = new Map<GrantRecord, string[]>();
    for (const [key, grant] of assignment) {
      byGrant.set(grant, [...(byGrant.get(grant) ?? []), key]);
    }
    const values = new Map<string, string>();
    for (const [grant, keys] of byGrant) {
      withGrantIdentity(grant.keyPath, grant.vaultPath, (vault) => {
        for (const key of keys) {
          const value = vault.get(key);
          if (value === null) {
            throw new Error(`${key}: not found or outside grant ${grant.id}'s scope`);
          }
          values.set(key, value);
        }
      });
    }
    return values;
  }

  // ---- murk_plan -----------------------------------------------------------
  bb.agents.registerTool({
    name: "murk_plan",
    description:
      "List the murk vault's secret schema — key names and tags only, as JSON. " +
      "Never returns secret values. Use murk_get to read keys covered by a grant.",
    presentation: {
      label: { pending: "Reading murk schema", completed: "Read murk schema" },
    },
    parameters: z.object({
      tags: z.array(z.string()).optional().describe("Only include keys carrying one of these tags"),
    }),
    async execute({ tags }, { threadId }) {
      try {
        const target = await resolveThreadTarget(threadId);
        const vaultPath = canonicalVault((await vaultOverride()) ?? path.join(target.worktree, ".murk"));
        const entries = await agentPlan(vaultPath, tags);
        // Key names and tags only — no descriptions, examples, paths, or
        // grant annotations. Values never existed on this path at all.
        const schema = entries.map((entry) => ({ key: entry.key, tags: entry.tags ?? [] }));
        return JSON.stringify({ entries: schema }, null, 2);
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  });

  // ---- murk_get ------------------------------------------------------------
  bb.agents.registerTool({
    name: "murk_get",
    description:
      "Fetch granted murk secrets. By default the values are written to a 0600 dotenv file " +
      "(.murk-<threadId>.env) in this thread's worktree and only key names + the file path are returned; " +
      "values appear inline only for keys covered by a reveal grant. Keys outside the thread's grants fail closed.",
    instructions:
      "murk_get delivers secrets as a dotenv file by default — source it or pass it to tools; " +
      "never print its contents. The file is deleted when the thread goes idle, so re-fetch in a later " +
      "turn instead of caching values. Treat any inline revealed value as sensitive: never echo, log, or commit it.",
    presentation: {
      label: { pending: "Fetching murk secrets", completed: "Fetched murk secrets" },
    },
    parameters: z.object({
      keys: z
        .array(z.string().regex(KEY_NAME_PATTERN))
        .min(1)
        .optional()
        .describe("Key names to fetch; omit to fetch every key granted to this thread"),
    }),
    async execute({ keys }, { threadId, projectId }) {
      try {
        const target = await resolveThreadTarget(threadId);
        const { allowRevealGrants } = await settings.get();
        const grants = store.activeFor(projectId, threadId);
        if (grants.length === 0) {
          return toolError(
            "no active grant covers this thread — ask the user to mint one with: bb murk grant mint --keys KEY[,KEY…]",
          );
        }
        const requested = keys ?? [...new Set(grants.flatMap((grant) => grant.keys))];
        const assignment = assignGrants(requested, grants, allowRevealGrants);
        const values = decryptAssigned(assignment);

        const revealKeys = requested.filter((key) => allowRevealGrants && assignment.get(key)?.reveal);
        const fileKeys = requested.filter((key) => !revealKeys.includes(key));

        const filePath = path.join(target.worktree, deliveryFilename(threadId));
        let deliveredToFile: string[] = [];
        if (fileKeys.length > 0) {
          // Merge with keys already delivered to this thread's file so a second
          // murk_get does not clobber the first. Values are always re-read from
          // the vault; stale (expired/revoked) merge keys are dropped silently.
          const previous = store
            .deliveriesFor(threadId)
            .filter((delivery) => delivery.filePath === filePath)
            .flatMap((delivery) => delivery.keys)
            .filter((key) => !requested.includes(key));
          const mergeValues = new Map<string, string>();
          for (const key of previous) {
            try {
              const merged = decryptAssigned(assignGrants([key], grants, false));
              const value = merged.get(key);
              if (value !== undefined) mergeValues.set(key, value);
            } catch {
              // dropped from the merged file: no longer covered
            }
          }
          deliveredToFile = [...new Set([...fileKeys, ...mergeValues.keys()])].sort();
          const entries = deliveredToFile.map((key): readonly [string, string] => {
            const value = values.get(key) ?? mergeValues.get(key);
            if (value === undefined) throw new Error(`${key}: lost during delivery merge`);
            return [key, value] as const;
          });
          // Invariant: never write over or delete bytes the plugin did not
          // write, across the file's whole life. No delivery record → the
          // first write is create-only (an existing file belongs to the
          // user). Owned path → CAS against the sha256 of the plugin's own
          // last write, so a file the user replaced after delivery is left
          // alone and ownership is relinquished.
          const owning = store.deliveriesFor(threadId).find((delivery) => delivery.filePath === filePath);
          const saved = await bb.sdk.files.write({
            hostId: target.hostId,
            path: filePath,
            rootPath: target.worktree,
            content: renderDotenv(entries),
            mode: 0o600,
            expectedSha256: owning ? owning.sha256 : null,
          });
          if (saved.outcome === "conflict") {
            if (owning) {
              store.forgetDelivery(threadId, filePath);
              return toolError(
                `the file at ${filePath} was modified externally since the plugin wrote it — ` +
                  "it will not be touched again; move it aside and call murk_get again",
              );
            }
            return toolError(
              `a file already exists at ${filePath} that this plugin did not create — ` +
                "move it aside (or delete it) and call murk_get again",
            );
          }
          store.recordDelivery({
            threadId,
            hostId: target.hostId,
            rootPath: target.worktree,
            filePath,
            keys: deliveredToFile,
            sha256: saved.sha256,
          });
        }

        const result: Record<string, unknown> = {};
        if (fileKeys.length > 0) {
          result.file = filePath;
          result.delivered = deliveredToFile;
          result.note = "values are in the file only (mode 0600); it is deleted when this thread goes idle — do not commit it";
        }
        if (revealKeys.length > 0) {
          result.revealed = Object.fromEntries(revealKeys.map((key) => [key, values.get(key)]));
        }
        return JSON.stringify(result, null, 2);
      } catch (error) {
        return toolError(error instanceof Error ? error.message : String(error));
      }
    },
  });

  // ---- delivered-file cleanup ----------------------------------------------
  bb.events.on("thread.idle", async ({ thread }) => {
    const deliveries = store.deliveriesFor(thread.id);
    if (deliveries.length === 0) return;
    let removed = 0;
    for (const delivery of deliveries) {
      // files.remove has no CAS guard, so read-compare-then-remove: delete
      // only when the file still hashes to the plugin's own last write.
      // Mismatch, missing file, or read error → leave the file alone.
      try {
        const current = await bb.sdk.files.read({ hostId: delivery.hostId, path: delivery.filePath });
        if (current.sha256 === delivery.sha256) {
          await bb.sdk.files.remove({
            hostId: delivery.hostId,
            path: delivery.filePath,
            rootPath: delivery.rootPath,
          });
          removed++;
        } else {
          bb.log.info(`leaving ${delivery.filePath} in place: modified externally since delivery`);
        }
      } catch (error) {
        // Already gone (or the worktree was destroyed) — nothing to clean.
        bb.log.debug(
          `delivery cleanup for ${delivery.filePath}: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
    store.clearDeliveries(thread.id);
    bb.log.info(`removed ${removed} delivered env file(s) for idle thread ${thread.id}`);
  });

  // ---- bb murk CLI ---------------------------------------------------------
  bb.cli.register({
    name: "murk",
    summary: "Scoped murk secret grants for agent threads",
    commands: [
      {
        name: "grant-mint",
        summary: "Mint a scoped grant (ephemeral murk identity for exactly the named keys)",
        usage: "bb murk grant mint --keys KEY[,KEY…] [--ttl 2h] [--thread <threadId>] [--project <projectId>] [--reveal]",
      },
      {
        name: "grant-list",
        summary: "List grants with scope, keys, expiry, and reveal status",
        usage: "bb murk grant list [--all]",
      },
      {
        name: "grant-revoke",
        summary: "Revoke a grant: remove its vault identity and delete its key file",
        usage: "bb murk grant revoke <grantId>",
      },
    ],
    async run(argv, ctx) {
      try {
        if (argv[0] !== "grant") {
          return { exitCode: 1, stderr: "usage: bb murk grant <mint|list|revoke> …" };
        }
        const sub = argv[1];
        const rest = argv.slice(2);
        if (sub === "mint") return await cliMint(rest, ctx.cwd, ctx.threadId, ctx.projectId);
        if (sub === "list") return await cliList(rest.includes("--all"));
        if (sub === "revoke") return await cliRevoke(rest[0]);
        return { exitCode: 1, stderr: "usage: bb murk grant <mint|list|revoke> …" };
      } catch (error) {
        return { exitCode: 1, stderr: `murk: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  });

  interface MintFlags {
    keys: string[];
    ttl: string;
    thread: string | null;
    project: string | null;
    reveal: boolean;
  }

  function parseMintFlags(argv: string[]): MintFlags {
    const flags: MintFlags = { keys: [], ttl: "2h", thread: null, project: null, reveal: false };
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      const takeValue = (): string => {
        const value = argv[++i];
        if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
        return value;
      };
      if (arg === "--keys") flags.keys.push(...takeValue().split(",").map((key) => key.trim()).filter(Boolean));
      else if (arg === "--ttl") flags.ttl = takeValue();
      else if (arg === "--thread") flags.thread = takeValue();
      else if (arg === "--project") flags.project = takeValue();
      else if (arg === "--reveal") flags.reveal = true;
      else throw new Error(`unknown flag ${arg}`);
    }
    if (flags.keys.length === 0) throw new Error("--keys is required (fails closed): name every key this grant may read");
    for (const key of flags.keys) {
      if (!KEY_NAME_PATTERN.test(key)) throw new Error(`${key} is not a valid secret key name`);
    }
    return flags;
  }

  async function cliMint(
    argv: string[],
    cwd: string | undefined,
    ctxThreadId: string | undefined,
    ctxProjectId: string | undefined,
  ): Promise<{ exitCode: number; stdout?: string; stderr?: string }> {
    const flags = parseMintFlags(argv);
    const { defaultScope, allowRevealGrants } = await settings.get();

    if (flags.reveal && !allowRevealGrants) {
      return {
        exitCode: 1,
        stderr: "murk: reveal grants are disabled (plugin setting allowRevealGrants=false)",
      };
    }

    // Resolve project + vault. Grants default to project scope; --thread (or
    // the defaultScope=thread setting, when invoked from a thread) narrows.
    let projectId = flags.project ?? ctxProjectId ?? null;
    let worktree: string | null = null;
    const contextThreadId = flags.thread ?? ctxThreadId ?? null;
    if (contextThreadId) {
      const thread = await bb.sdk.threads.get({ threadId: contextThreadId });
      projectId ??= thread.projectId;
      if (thread.environmentId) {
        const environment = await bb.sdk.environments.get({ environmentId: thread.environmentId });
        worktree = environment.path;
      }
    }
    if (!projectId) {
      return { exitCode: 1, stderr: "murk: cannot resolve a project — pass --project <projectId>" };
    }

    let vaultPath = await vaultOverride();
    if (!vaultPath && worktree && existsSync(path.join(worktree, ".murk"))) {
      vaultPath = path.join(worktree, ".murk");
    }
    if (!vaultPath && cwd && existsSync(path.join(cwd, ".murk"))) {
      vaultPath = path.join(cwd, ".murk");
    }
    if (!vaultPath) {
      return {
        exitCode: 1,
        stderr: "murk: no vault found — run from a directory containing .murk, or set the plugin's vaultPath setting",
      };
    }
    if (!existsSync(vaultPath)) {
      return { exitCode: 1, stderr: `murk: vault not found at ${vaultPath}` };
    }
    // murk's stored-key auto-discovery hashes the absolute vault path, so
    // symlinked segments (macOS /var/folders → /private/var) must be resolved.
    vaultPath = canonicalVault(vaultPath);

    const threadId = flags.thread ?? (defaultScope === "thread" && ctxThreadId ? ctxThreadId : null);

    const id = store.newGrantId();
    const murkName = `bb-${id}`;
    const keyFilePath = path.join(agentKeysDir(), `${id}.key`);
    const { expiresAt } = await mintGrant({
      vaultPath,
      name: murkName,
      keys: flags.keys,
      ttl: flags.ttl,
      keyFilePath,
    });
    const grant = store.create({
      id,
      murkName,
      projectId,
      threadId,
      keys: flags.keys,
      reveal: flags.reveal,
      vaultPath,
      keyPath: keyFilePath,
      expiresAt,
    });

    const scope = grant.threadId ? `thread ${grant.threadId}` : `project ${grant.projectId}`;
    const delivery = grant.reveal ? "reveal (murk_get may return these values inline)" : "file-only (dotenv delivery)";
    return {
      exitCode: 0,
      stdout: [
        `minted grant ${grant.id} (${murkName})`,
        `  keys:     ${grant.keys.join(", ")}`,
        `  scope:    ${scope}`,
        `  expires:  ${grant.expiresAt}`,
        `  delivery: ${delivery}`,
        `  vault:    ${grant.vaultPath}`,
        "",
        "agents in scope can now call murk_get; revoke with: bb murk grant revoke " + grant.id,
      ].join("\n"),
    };
  }

  async function cliList(includeRevoked: boolean): Promise<{ exitCode: number; stdout: string }> {
    const grants = store.list({ includeRevoked });
    if (grants.length === 0) return { exitCode: 0, stdout: "no grants" };
    const lines = grants.map((grant) => {
      const scope = grant.threadId ? `thread ${grant.threadId}` : `project ${grant.projectId}`;
      const status = grant.revokedAt ? "revoked" : isExpired(grant.expiresAt) ? "EXPIRED" : "active";
      const reveal = grant.reveal ? "reveal" : "file-only";
      return `${grant.id}  ${status}  ${reveal}  ${scope}  expires ${grant.expiresAt}  keys: ${grant.keys.join(", ")}`;
    });
    return { exitCode: 0, stdout: lines.join("\n") };
  }

  async function cliRevoke(id: string | undefined): Promise<{ exitCode: number; stdout?: string; stderr?: string }> {
    if (!id) return { exitCode: 1, stderr: "usage: bb murk grant revoke <grantId>" };
    const grant = store.get(id);
    if (!grant) return { exitCode: 1, stderr: `murk: no grant ${id}` };
    if (grant.revokedAt) return { exitCode: 0, stdout: `grant ${id} is already revoked` };
    await revokeGrant(grant.vaultPath, grant.murkName);
    rmSync(grant.keyPath, { force: true });
    store.markRevoked(id);
    return {
      exitCode: 0,
      stdout:
        `revoked grant ${id} (${grant.murkName}) and deleted its key file\n` +
        `note: rotate the affected keys (murk rotate KEY) — old vault versions in git history remain readable`,
    };
  }

  // The murk CLI is required for minting, revocation, and the schema; surface
  // its absence as a configuration problem instead of failing per call.
  void runMurk(["--version"]).catch(() => {
    bb.status.needsConfiguration("The murk CLI is not on the bb server's PATH — install murk, then reload the plugin.");
  });

  // Warm the local-host gate so the first thread resolution after load
  // already knows the primary host (bb binds bb.sdk before loading plugins).
  void primaryHostId();

  bb.log.info("murk plugin loaded");
}
