-- Pot Log Database Schema
-- Run via: wrangler d1 execute potlog-db --file=schema.sql

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  display_name TEXT DEFAULT '',
  avatar_emoji TEXT DEFAULT '🌱',
  bio TEXT DEFAULT '',
  settings TEXT DEFAULT '{}',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grows (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  strain TEXT DEFAULT '',
  medium TEXT DEFAULT 'Soil',
  environment TEXT DEFAULT 'Indoor',
  completed INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS plants (
  id TEXT PRIMARY KEY,
  grow_id TEXT NOT NULL,
  name TEXT NOT NULL,
  strain_override TEXT DEFAULT '',
  stage TEXT NOT NULL DEFAULT 'germination',
  milestones TEXT DEFAULT '[]',
  dismissed_prompts TEXT DEFAULT '[]',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
  id TEXT PRIMARY KEY,
  plant_id TEXT NOT NULL,
  text TEXT DEFAULT '',
  photo TEXT DEFAULT NULL,
  stage TEXT NOT NULL,
  timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_grows_user ON grows(user_id);
CREATE INDEX IF NOT EXISTS idx_plants_grow ON plants(grow_id);
CREATE INDEX IF NOT EXISTS idx_notes_plant ON notes(plant_id);
