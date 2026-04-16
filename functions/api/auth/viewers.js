import { requireAuth, isEditor, hashPassword, genId, json, LIMITS } from '../../_shared/auth.js';

// GET /api/auth/viewers — list all viewer accounts (editor only)
export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden' }, 403);

  const result = await env.DB.prepare(
    "SELECT id, username, display_name, created_at FROM users WHERE role = 'viewer' ORDER BY created_at DESC"
  ).all();

  return json({ viewers: result.results });
}

// POST /api/auth/viewers — create a viewer account (editor only)
export async function onRequestPost({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden' }, 403);

  const { username, password } = await request.json();

  if (!username || typeof username !== 'string')
    return json({ error: 'Username is required' }, 400);

  const clean = username.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (clean.length < 2 || clean.length > LIMITS.username)
    return json({ error: 'Username must be 2-30 characters (letters, numbers, underscores)' }, 400);

  if (!password || typeof password !== 'string' || password.length < 8)
    return json({ error: 'Password must be at least 8 characters' }, 400);

  if (password.length > LIMITS.password)
    return json({ error: 'Password is too long' }, 400);

  // Use a synthetic email so the UNIQUE constraint is satisfied
  const email = `${clean}@potlog.viewer`;

  const existing = await env.DB.prepare(
    'SELECT id FROM users WHERE username = ? OR email = ?'
  ).bind(clean, email).first();

  if (existing) return json({ error: 'A viewer with that username already exists' }, 409);

  const id = genId();
  const salt = genId() + genId();
  const passwordHash = await hashPassword(password, salt);
  const now = Date.now();
  const displayName = username.trim().slice(0, LIMITS.displayName);

  await env.DB.prepare(
    'INSERT INTO users (id, username, email, password_hash, salt, display_name, avatar_emoji, bio, settings, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, clean, email, passwordHash, salt, displayName, '👁️', '', '{}', 'viewer', now).run();

  return json({ viewer: { id, username: clean, display_name: displayName, created_at: now } }, 201);
}

// DELETE /api/auth/viewers/:id — remove a viewer account (editor only)
export async function onRequestDelete({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden' }, 403);

  // Confirm the target is actually a viewer (not an editor)
  const target = await env.DB.prepare(
    "SELECT id FROM users WHERE id = ? AND role = 'viewer'"
  ).bind(params.id).first();

  if (!target) return json({ error: 'Viewer not found' }, 404);

  // Delete their sessions first
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(params.id).run();

  return json({ ok: true });
}
