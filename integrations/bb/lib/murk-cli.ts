// Wrappers around the murk CLI for the operations the Node binding does not
// expose: minting and revoking agent grants, and the value-free schema
// (`murk agent plan`). All of these run server-side against a server-local
// vault file — the plugin's v1 contract is local-host-only.
import { execFile } from "node:child_process";
import { chmodSync } from "node:fs";
import * as path from "node:path";
import { z } from "zod";

export interface MurkResult {
  code: number;
  stdout: string;
  stderr: string;
}

const planEntrySchema = z.object({
  key: z.string(),
  description: z.string().optional(),
  example: z.string().optional(),
  tags: z.array(z.string()).optional(),
});
const planSchema = z.object({ entries: z.array(planEntrySchema) });
export type PlanEntry = z.infer<typeof planEntrySchema>;

const grantInfoSchema = z.object({
  name: z.string(),
  scope: z.array(z.string()),
  issued_at: z.string(),
  expires_at: z.string(),
  expired: z.boolean(),
});
export type MurkGrantInfo = z.infer<typeof grantInfoSchema>;

const MURK_TIMEOUT_MS = 30_000;

/**
 * Run `murk <args>`. Never a shell. The environment is inherited except:
 * - MURK_AGENT / MURK_STRICT are stripped — these are operator-context
 *   invocations (mint/revoke need the operator identity; plan needs no key),
 *   and a stray agent flag would force strict mode and break the stored-key
 *   fallback.
 * - MURK_VAULT is stripped — every call passes --vault explicitly.
 * - With `keyless: true`, MURK_KEY / MURK_KEY_FILE are stripped too, so the
 *   call can never depend on (or exercise) an identity.
 *
 * `cwd` should be the directory holding the vault: murk resolves the
 * operator's stored-key fallback relative to the vault's project directory.
 */
export function runMurk(args: string[], options?: { keyless?: boolean; cwd?: string }): Promise<MurkResult> {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.MURK_AGENT;
  delete env.MURK_STRICT;
  delete env.MURK_VAULT;
  if (options?.keyless) {
    delete env.MURK_KEY;
    delete env.MURK_KEY_FILE;
  }
  const { promise, resolve, reject } = Promise.withResolvers<MurkResult>();
  execFile(
    "murk",
    args,
    { cwd: options?.cwd, env: env as NodeJS.ProcessEnv, timeout: MURK_TIMEOUT_MS, maxBuffer: 1 << 20 },
    (error, stdout, stderr) => {
      if (error?.code === "ENOENT") {
        reject(new Error("the murk CLI is not on the bb server's PATH — install murk and reload the plugin"));
        return;
      }
      const code = typeof error?.code === "number" ? error.code : error ? 1 : 0;
      resolve({ code, stdout, stderr });
    },
  );
  return promise;
}

function murkError(what: string, result: MurkResult): Error {
  const detail = (result.stderr.trim() || result.stdout.trim()).replace(/\s+/g, " ");
  return new Error(`${what} failed: ${detail || `murk exited ${result.code}`}`);
}

/**
 * Mint a scoped grant in the vault and write its ephemeral identity to
 * `keyFilePath` (0600). Uses the operator identity the server process holds
 * (environment key or murk's stored key). Returns the grant's expiry.
 */
export async function mintGrant(options: {
  vaultPath: string;
  name: string;
  keys: string[];
  ttl: string;
  keyFilePath: string;
}): Promise<{ expiresAt: string }> {
  const args = ["agent", "grant", "--name", options.name, "--ttl", options.ttl, "--out", options.keyFilePath, "--vault", options.vaultPath];
  for (const key of options.keys) args.push("--only", key);
  const result = await runMurk(args, { cwd: path.dirname(options.vaultPath) });
  if (result.code !== 0) throw murkError(`minting grant for ${options.keys.join(", ")}`, result);
  // murk writes the key file itself; clamp to 0600 regardless.
  chmodSync(options.keyFilePath, 0o600);

  const grants = await listGrants(options.vaultPath);
  const minted = grants.find((grant) => grant.name === options.name);
  if (!minted) throw new Error(`grant ${options.name} was minted but is missing from 'murk agent ls'`);
  return { expiresAt: minted.expires_at };
}

export async function listGrants(vaultPath: string): Promise<MurkGrantInfo[]> {
  const result = await runMurk(["agent", "ls", "--json", "--vault", vaultPath], { cwd: path.dirname(vaultPath) });
  if (result.code !== 0) throw murkError("listing grants", result);
  return z.array(grantInfoSchema).parse(JSON.parse(result.stdout));
}

/** Revoke a grant by its murk name. Missing grants are treated as already revoked. */
export async function revokeGrant(vaultPath: string, name: string): Promise<void> {
  const result = await runMurk(["agent", "revoke", name, "--vault", vaultPath], { cwd: path.dirname(vaultPath) });
  if (result.code !== 0 && !/no grant named|not found/i.test(result.stderr + result.stdout)) {
    throw murkError(`revoking grant ${name}`, result);
  }
}

/**
 * The value-free schema: key names, descriptions, examples, tags. Needs no
 * key — murk reads only the vault's plaintext schema.
 */
export async function agentPlan(vaultPath: string, tags?: string[]): Promise<PlanEntry[]> {
  const args = ["agent", "plan", "--json", "--vault", vaultPath];
  for (const tag of tags ?? []) args.push("--tag", tag);
  const result = await runMurk(args, { keyless: true, cwd: path.dirname(vaultPath) });
  if (result.code !== 0) throw murkError("reading the vault schema", result);
  return planSchema.parse(JSON.parse(result.stdout)).entries;
}
