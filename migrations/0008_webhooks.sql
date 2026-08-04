-- D1 schema for the WebHook test tool
-- Uses existing users and sessions tables from 0001_pastebin.sql

CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY, -- random slug in the capture URL (/h/<id>)
  user_id TEXT NOT NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_webhooks_user ON webhooks(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS webhook_events (
  id TEXT PRIMARY KEY,
  webhook_id TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  headers TEXT NOT NULL, -- JSON object: header name -> value
  query TEXT NOT NULL,   -- JSON object: query param -> value
  body TEXT NOT NULL DEFAULT '',
  ip TEXT,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_webhook_events_webhook_created ON webhook_events(webhook_id, created_at DESC);
