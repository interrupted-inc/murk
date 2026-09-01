// The murk Node binding (@interrupted/murk-secrets) is a napi native module,
// which esbuild cannot bundle — so it is loaded at runtime through
// createRequire, resolved from the plugin's own node_modules. It stays in
// `dependencies` so path and git installs have it on disk.
import { createRequire } from "node:module";

/** The subset of the binding's Vault class this plugin uses (see node/index.d.ts). */
export interface MurkVault {
  /** Decrypted value, or null when the key is absent or outside the identity's scope. */
  get(key: string): string | null;
  keys(): string[];
  has(key: string): boolean;
}

interface MurkBinding {
  load(vaultPath?: string | null): MurkVault;
  hasIdentity(): boolean;
}

const requireBinding = createRequire(import.meta.url);
let cached: MurkBinding | null = null;

function binding(): MurkBinding {
  if (!cached) {
    try {
      cached = requireBinding("@interrupted/murk-secrets") as MurkBinding;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `the @interrupted/murk-secrets native binding is unavailable (${message}); ` +
          `reinstall the plugin with its dependencies`,
      );
    }
  }
  return cached;
}

/**
 * Load a vault as a specific grant identity and run `fn` against it.
 *
 * The binding reads MURK_KEY / MURK_KEY_FILE from the process environment at
 * load() time, so the grant key is swapped in around the synchronous load and
 * restored in a finally block. Node is single-threaded and load() is
 * synchronous, so no other code observes the swapped environment. MURK_AGENT=1
 * marks the load as an agent context: murk forces strict mode and never falls
 * back to the operator's stored key.
 *
 * TTL expiry and the vault's agent allow-tag policy are enforced by murk
 * itself inside the binding — an expired grant fails to load, and a
 * policy-forbidden key throws on get().
 */
export function withGrantIdentity<T>(
  keyFilePath: string,
  vaultPath: string,
  fn: (vault: MurkVault) => T,
): T {
  const saved: Record<string, string | undefined> = {
    MURK_KEY: process.env.MURK_KEY,
    MURK_KEY_FILE: process.env.MURK_KEY_FILE,
    MURK_AGENT: process.env.MURK_AGENT,
    MURK_STRICT: process.env.MURK_STRICT,
  };
  delete process.env.MURK_KEY;
  process.env.MURK_KEY_FILE = keyFilePath;
  process.env.MURK_AGENT = "1";
  try {
    return fn(binding().load(vaultPath));
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
