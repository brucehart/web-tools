-- D1 schema for Boards tool
-- Uses existing users and sessions tables from 0001_pastebin.sql

CREATE TABLE IF NOT EXISTS boards (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_boards_user_sort ON boards(user_id, sort_order ASC, updated_at DESC);

CREATE TABLE IF NOT EXISTS board_lists (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL,
  title TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_board_lists_board_sort ON board_lists(board_id, sort_order ASC, created_at ASC);

CREATE TABLE IF NOT EXISTS board_cards (
  id TEXT PRIMARY KEY,
  board_id TEXT NOT NULL,
  list_id TEXT NOT NULL,
  title TEXT NOT NULL,
  markdown TEXT NOT NULL DEFAULT '',
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (board_id) REFERENCES boards(id) ON DELETE CASCADE,
  FOREIGN KEY (list_id) REFERENCES board_lists(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_board_cards_list_sort ON board_cards(list_id, sort_order ASC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_board_cards_board_list_sort ON board_cards(board_id, list_id, sort_order ASC);

CREATE TABLE IF NOT EXISTS card_images (
  id TEXT PRIMARY KEY,
  card_id TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  data_url TEXT NOT NULL,
  alt_text TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  FOREIGN KEY (card_id) REFERENCES board_cards(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_card_images_card_sort ON card_images(card_id, sort_order ASC, created_at ASC);
