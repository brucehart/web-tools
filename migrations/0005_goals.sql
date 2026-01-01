-- D1 schema for Daily Goal Tracker
-- Goals are user-scoped and store per-day statuses

CREATE TABLE IF NOT EXISTS goals (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_goals_user ON goals(user_id);

CREATE TABLE IF NOT EXISTS goal_entries (
  goal_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  day TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('complete','partial','missed')),
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  PRIMARY KEY (goal_id, day),
  FOREIGN KEY (goal_id) REFERENCES goals(id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_goal_entries_user ON goal_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_goal_entries_goal ON goal_entries(goal_id);
