import { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
/** 256-bit random secret, URL-safe. */
export const newSecret = () => crypto.randomBytes(32).toString('base64url');
export const now = () => new Date().toISOString();

export function openDb(path) {
  const db = new DatabaseSync(path);
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS devices (
      device_id    TEXT PRIMARY KEY,
      name         TEXT,
      platform     TEXT,
      hostname     TEXT,
      secret_hash  TEXT NOT NULL,
      created_at   TEXT NOT NULL,
      revoked_at   TEXT,
      last_seen    TEXT,
      capabilities TEXT
    );
    CREATE TABLE IF NOT EXISTS client_tokens (
      client_id  TEXT PRIMARY KEY,
      token_hash TEXT NOT NULL,
      is_admin   INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      revoked_at TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      session_id TEXT PRIMARY KEY,
      client_id  TEXT NOT NULL,
      device_id  TEXT,
      created_at TEXT NOT NULL,
      last_seen  TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS pairing_requests (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      code       TEXT NOT NULL,
      poll_hash  TEXT NOT NULL UNIQUE,
      device_id  TEXT NOT NULL,
      name       TEXT,
      hostname   TEXT,
      platform   TEXT,
      remote     TEXT,
      created_at TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      status     TEXT NOT NULL DEFAULT 'pending'  -- pending | approved | denied | consumed
    );
    CREATE TABLE IF NOT EXISTS web_sessions (
      token_hash TEXT PRIMARY KEY,
      csrf       TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS client_defaults (
      client_id  TEXT PRIMARY KEY,
      device_id  TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id          TEXT PRIMARY KEY,
      client_secret_hash TEXT,
      client_name        TEXT NOT NULL,
      redirect_uris      TEXT NOT NULL,
      auth_method        TEXT NOT NULL DEFAULT 'none',
      created_at         TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code_hash      TEXT PRIMARY KEY,
      client_id      TEXT NOT NULL,
      redirect_uri   TEXT NOT NULL,
      code_challenge TEXT NOT NULL,
      expires_at     INTEGER NOT NULL,
      used           INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS oauth_tokens (
      token_hash TEXT PRIMARY KEY,
      kind       TEXT NOT NULL,
      client_id  TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp   TEXT NOT NULL,
      client_id   TEXT,
      device_id   TEXT,
      tool        TEXT,
      request_id  TEXT,
      duration_ms INTEGER,
      status      TEXT,
      error_code  TEXT
    );
  `);
  return db;
}
