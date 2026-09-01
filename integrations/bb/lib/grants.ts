// Grant metadata lives in the plugin's SQLite database; identity key material
// NEVER does — keys are 0600 files under the plugin data dir, and only their
// paths are recorded here.
import { randomBytes } from "node:crypto";
import { z } from "zod";

const keysSchema = z.array(z.string());

/** The better-sqlite3 surface this store uses (bb.storage.database()). */
export interface GrantDatabase {
  prepare(sql: string): {
    run(...params: unknown[]): unknown;
    get(...params: unknown[]): unknown;
    all(...params: unknown[]): unknown[];
  };
}

export const GRANT_MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    murk_name TEXT NOT NULL,
    project_id TEXT NOT NULL,
    thread_id TEXT,
    keys_json TEXT NOT NULL,
    reveal INTEGER NOT NULL DEFAULT 0,
    vault_path TEXT NOT NULL,
    key_path TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
  )`,
  `CREATE TABLE IF NOT EXISTS deliveries (
    thread_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    root_path TEXT NOT NULL,
    file_path TEXT NOT NULL,
    keys_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (thread_id, file_path)
  )`,
  // Content hash of the plugin's own last write, the CAS token proving the
  // file still holds bytes the plugin wrote. Appended (never edit shipped
  // statements): fresh databases create-then-alter, existing ones just alter.
  // Legacy rows default to '' — a hash that can never match, so the plugin
  // relinquishes those files instead of overwriting or deleting them.
  `ALTER TABLE deliveries ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''`,
];

export interface GrantRecord {
  id: string;
  murkName: string;
  projectId: string;
  /** null = project scope; otherwise the grant is narrowed to one thread. */
  threadId: string | null;
  keys: string[];
  reveal: boolean;
  vaultPath: string;
  keyPath: string;
  expiresAt: string;
  createdAt: string;
  revokedAt: string | null;
}

export interface DeliveryRecord {
  threadId: string;
  hostId: string;
  rootPath: string;
  filePath: string;
  keys: string[];
  sha256: string;
  updatedAt: string;
}

interface GrantRow {
  id: string;
  murk_name: string;
  project_id: string;
  thread_id: string | null;
  keys_json: string;
  reveal: number;
  vault_path: string;
  key_path: string;
  expires_at: string;
  created_at: string;
  revoked_at: string | null;
}

interface DeliveryRow {
  thread_id: string;
  host_id: string;
  root_path: string;
  file_path: string;
  keys_json: string;
  sha256: string;
  updated_at: string;
}

export function isExpired(expiresAt: string, now: Date = new Date()): boolean {
  const expiry = Date.parse(expiresAt);
  // An unparseable expiry fails closed.
  return Number.isNaN(expiry) || expiry <= now.getTime();
}

function toGrant(row: GrantRow): GrantRecord {
  return {
    id: row.id,
    murkName: row.murk_name,
    projectId: row.project_id,
    threadId: row.thread_id,
    keys: keysSchema.parse(JSON.parse(row.keys_json)),
    reveal: row.reveal === 1,
    vaultPath: row.vault_path,
    keyPath: row.key_path,
    expiresAt: row.expires_at,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
  };
}

export class GrantStore {
  constructor(private readonly db: GrantDatabase) {}

  newGrantId(): string {
    return `g${randomBytes(4).toString("hex")}`;
  }

  create(grant: Omit<GrantRecord, "createdAt" | "revokedAt">): GrantRecord {
    const createdAt = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO grants (id, murk_name, project_id, thread_id, keys_json, reveal, vault_path, key_path, expires_at, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        grant.id,
        grant.murkName,
        grant.projectId,
        grant.threadId,
        JSON.stringify(grant.keys),
        grant.reveal ? 1 : 0,
        grant.vaultPath,
        grant.keyPath,
        grant.expiresAt,
        createdAt,
      );
    return { ...grant, createdAt, revokedAt: null };
  }

  get(id: string): GrantRecord | null {
    const row = this.db.prepare(`SELECT * FROM grants WHERE id = ?`).get(id) as GrantRow | undefined;
    return row ? toGrant(row) : null;
  }

  list(options?: { includeRevoked?: boolean }): GrantRecord[] {
    const sql = options?.includeRevoked
      ? `SELECT * FROM grants ORDER BY created_at DESC`
      : `SELECT * FROM grants WHERE revoked_at IS NULL ORDER BY created_at DESC`;
    return (this.db.prepare(sql).all() as GrantRow[]).map(toGrant);
  }

  /**
   * Grants usable by one thread: unrevoked, unexpired, matching the thread's
   * project, and either project-scoped or narrowed to exactly this thread.
   */
  activeFor(projectId: string, threadId: string, now: Date = new Date()): GrantRecord[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM grants
         WHERE revoked_at IS NULL AND project_id = ? AND (thread_id IS NULL OR thread_id = ?)
         ORDER BY created_at DESC`,
      )
      .all(projectId, threadId) as GrantRow[];
    return rows.map(toGrant).filter((grant) => !isExpired(grant.expiresAt, now));
  }

  markRevoked(id: string): void {
    this.db.prepare(`UPDATE grants SET revoked_at = ? WHERE id = ?`).run(new Date().toISOString(), id);
  }

  recordDelivery(delivery: Omit<DeliveryRecord, "updatedAt">): void {
    this.db
      .prepare(
        `INSERT INTO deliveries (thread_id, host_id, root_path, file_path, keys_json, sha256, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(thread_id, file_path) DO UPDATE SET
           keys_json = excluded.keys_json, sha256 = excluded.sha256, updated_at = excluded.updated_at`,
      )
      .run(
        delivery.threadId,
        delivery.hostId,
        delivery.rootPath,
        delivery.filePath,
        JSON.stringify(delivery.keys),
        delivery.sha256,
        new Date().toISOString(),
      );
  }

  deliveriesFor(threadId: string): DeliveryRecord[] {
    const rows = this.db.prepare(`SELECT * FROM deliveries WHERE thread_id = ?`).all(threadId) as DeliveryRow[];
    return rows.map((row) => ({
      threadId: row.thread_id,
      hostId: row.host_id,
      rootPath: row.root_path,
      filePath: row.file_path,
      keys: keysSchema.parse(JSON.parse(row.keys_json)),
      sha256: row.sha256,
      updatedAt: row.updated_at,
    }));
  }

  /** Drop one delivery record — the plugin relinquishes ownership of that path. */
  forgetDelivery(threadId: string, filePath: string): void {
    this.db.prepare(`DELETE FROM deliveries WHERE thread_id = ? AND file_path = ?`).run(threadId, filePath);
  }

  clearDeliveries(threadId: string): void {
    this.db.prepare(`DELETE FROM deliveries WHERE thread_id = ?`).run(threadId);
  }
}
