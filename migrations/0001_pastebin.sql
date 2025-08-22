-- D1 schema for Pastebin tool
-- Users come from Google OAuth; we key by Google sub (string)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, -- google sub
  email TEXT,
  name TEXT,
  picture TEXT,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- Sessions map random token -> user id
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  expires_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Pastes
CREATE TABLE IF NOT EXISTS pastes (
  id TEXT PRIMARY KEY, -- slug
  user_id TEXT NOT NULL,
  title TEXT,
  content TEXT NOT NULL,
  visibility TEXT NOT NULL CHECK (visibility IN ('public','unlisted')),
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_pastes_visibility_created ON pastes(visibility, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pastes_user_created ON pastes(user_id, created_at DESC);

