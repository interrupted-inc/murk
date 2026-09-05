// Integration-style tests: real murk CLI (on PATH), real murk Node binding,
// real temp vault, fake bb plugin host. HOME is redirected to a temp dir so
// murk's stored operator key never touches the developer's real key directory.
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import type { PluginAgentConfigurationContext, PluginAgentToolResult } from "@get-bb/plugin-sdk";
import { createFakePluginHost, makeThreadResponse, type FakePluginHost } from "@get-bb/plugin-sdk/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { GRANT_MIGRATIONS, GrantStore, isExpired } from "./lib/grants";
import { renderDotenv } from "./lib/dotenv";
import plugin from "./server";

const THREAD_ID = "thread-test";
const PROJECT_ID = "project-test";
const LOCAL_HOST = "host_local";
const REMOTE_HOST = "host_remote";
const SECRET_VALUE = "sk-test-swordfish-12345";
const OTHER_VALUE = "other-secret-value-67890";

let tmpRoot: string;
let worktree: string;
let host: FakePluginHost;
const savedEnv: Record<string, string | undefined> = {};

function sha256(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

function murk(args: string[], input?: string): void {
  const result = spawnSync("murk", args, {
    cwd: worktree,
    input,
    encoding: "utf8",
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(`murk ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
}

function toolText(result: PluginAgentToolResult): { text: string; isError: boolean } {
  if (typeof result === "string") return { text: result, isError: false };
  const text = result.content.map((part) => ("text" in part ? part.text : "")).join("\n");
  return { text, isError: result.isError === true };
}

function configureContext(hostId: string): PluginAgentConfigurationContext {
  return {
    thread: { id: THREAD_ID, title: null, parentThreadId: null, sourceThreadId: null },
    project: { id: PROJECT_ID, kind: "standard" as const, name: "murk", gitRemoteUrl: null },
    environment: {
      id: "env_1",
      name: null,
      path: worktree,
      workspaceProvisionType: "managed-worktree" as const,
      branchName: null,
    },
    host: { id: hostId, name: "test-host" },
    provider: {
      id: "test-provider",
      model: "test-model",
      capabilities: { supportsNativeUserQuestion: false },
    },
    origin: { kind: null, pluginId: null },
  };
}

beforeAll(async () => {
  tmpRoot = mkdtempSync(path.join(tmpdir(), "bb-murk-test-"));
  const fakeHome = path.join(tmpRoot, "home");
  worktree = path.join(tmpRoot, "worktree");
  mkdirSync(fakeHome, { recursive: true });
  mkdirSync(worktree, { recursive: true });

  // Redirect murk's key storage and drop any identity inherited from the
  // developer shell (direnv commonly exports MURK_KEY_FILE in this repo).
  for (const name of ["HOME", "MURK_KEY", "MURK_KEY_FILE", "MURK_AGENT", "MURK_STRICT", "MURK_VAULT"]) {
    savedEnv[name] = process.env[name];
    delete process.env[name];
  }
  process.env.HOME = fakeHome;

  murk(["init"], "bb-plugin-tests\n");
  murk(["add", "TEST_API_KEY", "--desc", "Test API key", "--tag", "agents"], SECRET_VALUE);
  murk(["add", "OTHER_SECRET", "--desc", "Second key", "--tag", "agents"], OTHER_VALUE);

  host = createFakePluginHost({
    pluginId: "murk",
    dataDir: path.join(tmpRoot, "bb-data"),
    agentSkillIds: ["murk"],
    sdk: {
      system: {
        config: async () => ({ primaryHostId: LOCAL_HOST }),
      },
      threads: {
        get: async (args: { threadId: string }) =>
          args.threadId === "thread-remote"
            ? { id: args.threadId, projectId: PROJECT_ID, environmentId: "env_remote" }
            : { id: args.threadId, projectId: PROJECT_ID, environmentId: "env_1" },
      },
      environments: {
        get: async (args: { environmentId: string }) =>
          args.environmentId === "env_remote"
            ? { id: args.environmentId, hostId: REMOTE_HOST, path: worktree, projectId: PROJECT_ID }
            : { id: args.environmentId, hostId: LOCAL_HOST, path: worktree, projectId: PROJECT_ID },
      },
      files: {
        write: async (args: { path: string; content: string; mode?: number; expectedSha256?: string | null }) => {
          // Mirror the host's optimistic-concurrency guard: null = create-only,
          // a hash = write only when the current content still hashes to it.
          const exists = existsSync(args.path);
          const currentSha = exists ? sha256(readFileSync(args.path)) : null;
          if (args.expectedSha256 === null && exists) {
            return { outcome: "conflict", currentSha256: currentSha };
          }
          if (typeof args.expectedSha256 === "string" && args.expectedSha256 !== currentSha) {
            return { outcome: "conflict", currentSha256: currentSha };
          }
          writeFileSync(args.path, args.content, { mode: args.mode ?? 0o644 });
          return { outcome: "written", sha256: sha256(args.content), sizeBytes: args.content.length };
        },
        read: async (args: { path: string }) => {
          if (!existsSync(args.path)) throw new Error(`${args.path}: not found`);
          const content = readFileSync(args.path, "utf8");
          return { content, contentEncoding: "utf8", sha256: sha256(content), sizeBytes: content.length };
        },
        remove: async (args: { path: string }) => {
          rmSync(args.path, { force: true });
          return { ok: true };
        },
      },
    },
  });
  await plugin(host.bb);
}, 30_000);

afterAll(async () => {
  await host?.harness.lifecycle.dispose();
  for (const [name, value] of Object.entries(savedEnv)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(tmpRoot, { recursive: true, force: true });
});

describe("registrations", () => {
  it("registers both tools, the CLI, and the settings", () => {
    const { registrations } = host.harness.inspection;
    expect(registrations.agentTools.map((tool) => tool.name).sort()).toEqual(["murk_get", "murk_plan"]);
    expect(registrations.cli?.name).toBe("murk");
    expect(Object.keys(registrations.settingsDescriptors).sort()).toEqual([
      "allowRevealGrants",
      "defaultScope",
      "vaultPath",
    ]);
    expect(registrations.agentConfigurationProvider).not.toBeNull();
  });
});

describe("local-host gate", () => {
  it("offers tools and the skill on the local host only", async () => {
    // The factory warms the primary-host cache at load; a tool call would too.
    await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID });

    const local = await host.harness.behavior.resolveAgentConfiguration(configureContext(LOCAL_HOST));
    expect(local.tools.map((tool) => tool.name).sort()).toEqual(["murk_get", "murk_plan"]);
    expect(local.skills).toEqual(["murk"]);

    const remote = await host.harness.behavior.resolveAgentConfiguration(configureContext(REMOTE_HOST));
    expect(remote.tools).toEqual([]);
    expect(remote.skills).toEqual([]);
  });

  it("fails closed everywhere while the primary host is unknown", async () => {
    const dark = createFakePluginHost({
      pluginId: "murk",
      dataDir: path.join(tmpRoot, "bb-data-dark"),
      agentSkillIds: ["murk"],
      sdk: {
        system: {
          config: async () => {
            throw new Error("config unavailable");
          },
        },
      },
    });
    await plugin(dark.bb);
    const resolved = await dark.harness.behavior.resolveAgentConfiguration(configureContext(LOCAL_HOST));
    expect(resolved.tools).toEqual([]);
    expect(resolved.skills).toEqual([]);

    const result = toolText(
      await dark.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(result.isError).toBe(true);
    await dark.harness.lifecycle.dispose();
  });

  it("murk_get fails closed for a thread on a non-local host", async () => {
    const result = toolText(
      await host.harness.behavior.callAgentTool(
        "murk_get",
        {},
        { threadId: "thread-remote", projectId: PROJECT_ID },
      ),
    );
    expect(result.isError).toBe(true);
    expect(result.text).toContain("local-host-only");
  });
});

describe("grant lifecycle", () => {
  let fileGrantId: string;
  let revealGrantId: string;

  it("murk_get fails closed when no grant exists", async () => {
    const result = toolText(
      await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(result.isError).toBe(true);
    expect(result.text).toContain("no active grant");
  });

  it("mints a file-only grant via the CLI", async () => {
    const result = await host.harness.behavior.runCli(["grant", "mint", "--keys", "TEST_API_KEY", "--ttl", "1h"], {
      cwd: worktree,
      projectId: PROJECT_ID,
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const match = result.stdout.match(/minted grant (g[0-9a-f]{8})/);
    expect(match).not.toBeNull();
    fileGrantId = match![1];
    expect(result.stdout).toContain("file-only");
    expect(result.stdout).toContain("project " + PROJECT_ID);
  });

  it("murk_get delivers granted keys to a 0600 dotenv file and never returns the value", async () => {
    const result = toolText(
      await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(result.isError).toBe(false);
    expect(result.text).not.toContain(SECRET_VALUE);
    const parsed = JSON.parse(result.text) as { file: string; delivered: string[] };
    expect(parsed.delivered).toEqual(["TEST_API_KEY"]);
    expect(parsed.file).toBe(path.join(worktree, `.murk-${THREAD_ID}.env`));
    const written = readFileSync(parsed.file, "utf8");
    expect(written).toContain(`TEST_API_KEY='${SECRET_VALUE}'`);
  });

  it("never overwrites or deletes a pre-existing file it did not create", async () => {
    const foreignThread = "thread-preexist";
    const deliveryPath = path.join(worktree, `.murk-${foreignThread}.env`);
    writeFileSync(deliveryPath, "KEEP: user data, not plugin-created\n");

    const result = toolText(
      await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: foreignThread, projectId: PROJECT_ID }),
    );
    expect(result.isError).toBe(true);
    expect(result.text).toContain("did not create");
    expect(readFileSync(deliveryPath, "utf8")).toBe("KEEP: user data, not plugin-created\n");

    // Idle cleanup must not touch a path with no owning delivery record.
    const { errors } = await host.harness.behavior.emitThreadEvent("thread.idle", {
      thread: makeThreadResponse({ id: foreignThread }),
      lastAssistantText: null,
    });
    expect(errors).toEqual([]);
    expect(readFileSync(deliveryPath, "utf8")).toBe("KEEP: user data, not plugin-created\n");
    rmSync(deliveryPath);
  });

  it("murk_plan returns key names and tags only — no values, descriptions, or grant state", async () => {
    const result = toolText(
      await host.harness.behavior.callAgentTool("murk_plan", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(result.isError).toBe(false);
    expect(result.text).not.toContain(SECRET_VALUE);
    expect(result.text).not.toContain(OTHER_VALUE);
    // Descriptions set at vault setup must not leak through.
    expect(result.text).not.toContain("Test API key");
    expect(result.text).not.toContain(worktree);
    const parsed = JSON.parse(result.text) as { entries: Array<Record<string, unknown>> };
    expect(parsed.entries.map((entry) => entry.key).sort()).toEqual(["OTHER_SECRET", "TEST_API_KEY"]);
    for (const entry of parsed.entries) {
      expect(Object.keys(entry).sort()).toEqual(["key", "tags"]);
      expect(entry.tags).toEqual(["agents"]);
    }
    expect(Object.keys(parsed)).toEqual(["entries"]);
  });

  it("murk_get fails closed for a key outside every grant", async () => {
    const result = toolText(
      await host.harness.behavior.callAgentTool(
        "murk_get",
        { keys: ["OTHER_SECRET"] },
        { threadId: THREAD_ID, projectId: PROJECT_ID },
      ),
    );
    expect(result.isError).toBe(true);
    expect(result.text).toContain("OTHER_SECRET is not covered");
    expect(result.text).not.toContain(OTHER_VALUE);
  });

  it("a reveal grant returns its keys' values inline", async () => {
    const mint = await host.harness.behavior.runCli(
      ["grant", "mint", "--keys", "OTHER_SECRET", "--ttl", "1h", "--reveal"],
      { cwd: worktree, projectId: PROJECT_ID },
    );
    expect(mint.exitCode).toBe(0);
    revealGrantId = mint.stdout.match(/minted grant (g[0-9a-f]{8})/)![1];
    expect(mint.stdout).toContain("reveal");

    const result = toolText(
      await host.harness.behavior.callAgentTool(
        "murk_get",
        { keys: ["OTHER_SECRET"] },
        { threadId: THREAD_ID, projectId: PROJECT_ID },
      ),
    );
    expect(result.isError).toBe(false);
    const parsed = JSON.parse(result.text) as { revealed?: Record<string, string>; file?: string };
    expect(parsed.revealed?.OTHER_SECRET).toBe(OTHER_VALUE);
    expect(parsed.file).toBeUndefined();
  });

  it("allowRevealGrants=false refuses reveal mints and downgrades reveal grants to file delivery", async () => {
    await host.harness.behavior.setSettings({ allowRevealGrants: false });

    const refused = await host.harness.behavior.runCli(
      ["grant", "mint", "--keys", "TEST_API_KEY", "--reveal"],
      { cwd: worktree, projectId: PROJECT_ID },
    );
    expect(refused.exitCode).toBe(1);
    expect(refused.stderr).toContain("reveal grants are disabled");

    const result = toolText(
      await host.harness.behavior.callAgentTool(
        "murk_get",
        { keys: ["OTHER_SECRET"] },
        { threadId: THREAD_ID, projectId: PROJECT_ID },
      ),
    );
    expect(result.isError).toBe(false);
    const parsed = JSON.parse(result.text) as { revealed?: Record<string, string>; delivered?: string[]; file?: string };
    expect(parsed.revealed).toBeUndefined();
    expect(parsed.delivered).toContain("OTHER_SECRET");
    expect(result.text).not.toContain(OTHER_VALUE);

    await host.harness.behavior.setSettings({ allowRevealGrants: true });
  });

  it("grant list shows scope, keys, expiry, and reveal status", async () => {
    const result = await host.harness.behavior.runCli(["grant", "list"], {});
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain(fileGrantId);
    expect(result.stdout).toContain(revealGrantId);
    expect(result.stdout).toContain("file-only");
    expect(result.stdout).toContain("reveal");
    expect(result.stdout).toContain(`project ${PROJECT_ID}`);
    expect(result.stdout).toMatch(/expires \d{4}-\d{2}-\d{2}T/);
  });

  it("deletes delivered env files when the thread goes idle", async () => {
    const envFile = path.join(worktree, `.murk-${THREAD_ID}.env`);
    expect(existsSync(envFile)).toBe(true);
    const { errors } = await host.harness.behavior.emitThreadEvent("thread.idle", {
      thread: makeThreadResponse({ id: THREAD_ID }),
      lastAssistantText: null,
    });
    expect(errors).toEqual([]);
    expect(existsSync(envFile)).toBe(false);
  });

  it("relinquishes a delivered file the user replaced instead of overwriting it", async () => {
    const envFile = path.join(worktree, `.murk-${THREAD_ID}.env`);
    const first = toolText(
      await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(first.isError).toBe(false);
    writeFileSync(envFile, "FOREIGN CONTENT\n");

    const second = toolText(
      await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(second.isError).toBe(true);
    expect(second.text).toContain("modified externally");
    expect(readFileSync(envFile, "utf8")).toBe("FOREIGN CONTENT\n");

    // Ownership was relinquished — idle cleanup must leave the file alone.
    const { errors } = await host.harness.behavior.emitThreadEvent("thread.idle", {
      thread: makeThreadResponse({ id: THREAD_ID }),
      lastAssistantText: null,
    });
    expect(errors).toEqual([]);
    expect(readFileSync(envFile, "utf8")).toBe("FOREIGN CONTENT\n");
    rmSync(envFile);
  });

  it("idle cleanup leaves a replaced file in place even with a live delivery record", async () => {
    const envFile = path.join(worktree, `.murk-${THREAD_ID}.env`);
    const delivered = toolText(
      await host.harness.behavior.callAgentTool("murk_get", {}, { threadId: THREAD_ID, projectId: PROJECT_ID }),
    );
    expect(delivered.isError).toBe(false);
    writeFileSync(envFile, "FOREIGN AGAIN\n");

    const { errors } = await host.harness.behavior.emitThreadEvent("thread.idle", {
      thread: makeThreadResponse({ id: THREAD_ID }),
      lastAssistantText: null,
    });
    expect(errors).toEqual([]);
    expect(readFileSync(envFile, "utf8")).toBe("FOREIGN AGAIN\n");
    rmSync(envFile);
  });

  it("revoking a grant deletes its key file and closes access", async () => {
    const revoke = await host.harness.behavior.runCli(["grant", "revoke", fileGrantId], {});
    expect(revoke.exitCode).toBe(0);

    const keyFile = path.join(tmpRoot, "bb-data", "plugins", "murk", "agent-keys", `${fileGrantId}.key`);
    expect(existsSync(keyFile)).toBe(false);

    const result = toolText(
      await host.harness.behavior.callAgentTool(
        "murk_get",
        { keys: ["TEST_API_KEY"] },
        { threadId: THREAD_ID, projectId: PROJECT_ID },
      ),
    );
    expect(result.isError).toBe(true);
    expect(result.text).toContain("TEST_API_KEY is not covered");
  });
});

describe("vault-truth fail-closed", () => {
  // The plugin's SQLite bookkeeping can lag the real vault (key deleted after
  // minting, policy tightened, TTL clock skew). decryptAssigned must fail
  // closed on the vault's answer, not the plugin's cached grant record.
  it("murk_get fails closed when the vault no longer holds a key the grant still claims", async () => {
    murk(["add", "DOOMED_KEY", "--desc", "Short-lived key", "--tag", "agents"], "doomed-value-31337");
    const mint = await host.harness.behavior.runCli(
      ["grant", "mint", "--keys", "DOOMED_KEY", "--ttl", "1h"],
      { cwd: worktree, projectId: PROJECT_ID },
    );
    expect(mint.exitCode, mint.stderr).toBe(0);
    const grantId = mint.stdout.match(/minted grant (g[0-9a-f]{8})/)![1];

    // Delete the key from the vault directly — the plugin's grant record
    // still lists DOOMED_KEY as covered, so assignGrants lets it through and
    // only the vault read itself can refuse.
    murk(["rm", "DOOMED_KEY"]);

    const result = toolText(
      await host.harness.behavior.callAgentTool(
        "murk_get",
        { keys: ["DOOMED_KEY"] },
        { threadId: THREAD_ID, projectId: PROJECT_ID },
      ),
    );
    expect(result.isError).toBe(true);
    expect(result.text).toContain("not found or outside grant");
    expect(result.text).not.toContain("doomed-value-31337");
    // Nothing was delivered to a file either.
    expect(existsSync(path.join(worktree, `.murk-${THREAD_ID}.env`))).toBe(false);

    const revoke = await host.harness.behavior.runCli(["grant", "revoke", grantId], {});
    expect(revoke.exitCode).toBe(0);
  });
});

describe("grant store", () => {
  it("treats expired and unparseable expiries as inactive", () => {
    expect(isExpired("2000-01-01T00:00:00Z")).toBe(true);
    expect(isExpired("not-a-date")).toBe(true);
    expect(isExpired(new Date(Date.now() + 60_000).toISOString())).toBe(false);
  });

  it("activeFor filters revoked, expired, other-project, and other-thread grants", () => {
    const db = new Database(":memory:");
    for (const statement of GRANT_MIGRATIONS) db.exec(statement);
    const store = new GrantStore(db);
    const base = {
      keys: ["K"],
      reveal: false,
      vaultPath: "/v/.murk",
      keyPath: "/k",
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    };
    store.create({ ...base, id: "gaaaaaaa1", murkName: "bb-1", projectId: "p1", threadId: null });
    store.create({ ...base, id: "gaaaaaaa2", murkName: "bb-2", projectId: "p1", threadId: "t1" });
    store.create({ ...base, id: "gaaaaaaa3", murkName: "bb-3", projectId: "p1", threadId: "t2" });
    store.create({ ...base, id: "gaaaaaaa4", murkName: "bb-4", projectId: "p2", threadId: null });
    store.create({ ...base, id: "gaaaaaaa5", murkName: "bb-5", projectId: "p1", threadId: null, expiresAt: "2000-01-01T00:00:00Z" });
    store.create({ ...base, id: "gaaaaaaa6", murkName: "bb-6", projectId: "p1", threadId: null });
    store.markRevoked("gaaaaaaa6");

    const active = store.activeFor("p1", "t1").map((grant) => grant.id).sort();
    expect(active).toEqual(["gaaaaaaa1", "gaaaaaaa2"]);
  });

  it("upgrades a legacy deliveries table in place, defaulting sha256 to a never-matching value", () => {
    const db = new Database(":memory:");
    // A database that ran only the originally shipped statements…
    for (const statement of GRANT_MIGRATIONS.slice(0, 2)) db.exec(statement);
    db.prepare(
      `INSERT INTO deliveries (thread_id, host_id, root_path, file_path, keys_json, updated_at)
       VALUES ('t1', 'h1', '/w', '/w/.murk-t1.env', '["K"]', 'then')`,
    ).run();
    // …then applies the appended migration.
    for (const statement of GRANT_MIGRATIONS.slice(2)) db.exec(statement);

    const store = new GrantStore(db);
    const rows = store.deliveriesFor("t1");
    expect(rows).toHaveLength(1);
    expect(rows[0].keys).toEqual(["K"]);
    expect(rows[0].sha256).toBe("");
  });
});

describe("dotenv rendering", () => {
  it("single-quotes values and escapes embedded quotes", () => {
    const rendered = renderDotenv([
      ["A", "plain"],
      ["B", "it's got 'quotes'"],
      ["C", "multi\nline $HOME `cmd`"],
    ]);
    expect(rendered).toContain("A='plain'");
    expect(rendered).toContain("B='it'\\''s got '\\''quotes'\\'''");
    expect(rendered).toContain("C='multi\nline $HOME `cmd`'");
    expect(rendered).toContain("Do not commit");
  });
});
