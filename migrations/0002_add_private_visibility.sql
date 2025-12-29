-- Add 'private' visibility to pastes by recreating table with updated CHECK

-- Create new table with updated CHECK constraint
CREATE TABLE IF NOT EXISTS pastes_new (
  id TEXT PRIMARY KEY, -- slug
  user_id TEXT NOT NULL,
  title TEXT,
  content TEXT NOT NULL,
  visibility TEXT NOT NULL CHECK (visibility IN ('public','unlisted','private')),
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Copy data from old table
INSERT INTO pastes_new (id, user_id, title, content, visibility, created_at)
SELECT id, user_id, title, content, visibility, created_at FROM pastes;

-- Drop old indexes to avoid name conflicts
DROP INDEX IF EXISTS idx_pastes_visibility_created;
DROP INDEX IF EXISTS idx_pastes_user_created;

-- Replace old table
DROP TABLE pastes;
ALTER TABLE pastes_new RENAME TO pastes;

-- Recreate indexes
CREATE INDEX IF NOT EXISTS idx_pastes_visibility_created ON pastes(visibility, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pastes_user_created ON pastes(user_id, created_at DESC);
