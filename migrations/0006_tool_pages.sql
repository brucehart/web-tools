-- D1 schema for tool "pages" (Markdown Viewer + Euler Preview)
-- Uses existing users and sessions tables from 0001_pastebin.sql

CREATE TABLE IF NOT EXISTS tool_pages (
  id TEXT PRIMARY KEY,
  tool TEXT NOT NULL CHECK (tool IN ('markdown','euler')),
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_tool_pages_user_tool_updated ON tool_pages(user_id, tool, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_pages_user_tool_created ON tool_pages(user_id, tool, created_at DESC);

