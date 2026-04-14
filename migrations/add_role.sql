-- Migration: Add role column to users
-- Run via: wrangler d1 execute potlog-db --remote --file=migrations/add_role.sql

ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'editor';

-- Set all existing users to editor (they were the owner/creator)
UPDATE users SET role = 'editor' WHERE role IS NULL;
