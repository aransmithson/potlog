-- Migration: add login_attempts table for brute-force rate limiting
-- Run via: wrangler d1 execute potlog-db --file=migrations/add_login_attempts.sql

CREATE TABLE IF NOT EXISTS login_attempts (
  id TEXT PRIMARY KEY,
  identifier TEXT NOT NULL,
  ip TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_identifier ON login_attempts(identifier);
CREATE INDEX IF NOT EXISTS idx_login_attempts_created ON login_attempts(created_at);
