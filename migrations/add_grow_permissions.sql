-- Grow sharing / permissions table
-- Allows users to have different permission levels on different grows
-- Run via: wrangler d1 execute potlog-db --file=migrations/add_grow_permissions.sql

CREATE TABLE IF NOT EXISTS grow_permissions (
  id TEXT PRIMARY KEY,
  grow_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  permission TEXT NOT NULL DEFAULT 'view',  -- 'view' or 'edit'
  created_at INTEGER NOT NULL,
  UNIQUE(grow_id, user_id),
  FOREIGN KEY (grow_id) REFERENCES grows(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_grow_permissions_grow ON grow_permissions(grow_id);
CREATE INDEX IF NOT EXISTS idx_grow_permissions_user ON grow_permissions(user_id);
