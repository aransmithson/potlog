-- Viewer invitation tokens for email-based viewer onboarding
-- Run via: wrangler d1 execute potlog-db --file=migrations/add_viewer_invites.sql

CREATE TABLE IF NOT EXISTS viewer_invites (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  invited_by_user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_viewer_invites_email ON viewer_invites(email);
