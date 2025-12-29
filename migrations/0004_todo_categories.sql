-- Add category column to todos table
ALTER TABLE todos ADD COLUMN category TEXT DEFAULT 'personal';

-- Create index for category filtering
CREATE INDEX IF NOT EXISTS idx_todos_user_category ON todos(user_id, category);
