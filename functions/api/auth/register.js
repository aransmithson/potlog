import { hashPassword, genId, json, sessionCookie } from '../../../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  try {
    const { username, email, password } = await request.json();

    if (!username || !email || !password)
      return json({ error: 'Username, email and password are required' }, 400);

    if (username.length < 3)
      return json({ error: 'Username must be at least 3 characters' }, 400);

    if (password.length < 8)
      return json({ error: 'Password must be at least 8 characters' }, 400);

    if (!/^[a-zA-Z0-9_]+$/.test(username))
      return json({ error: 'Username can only contain letters, numbers and underscores' }, 400);

    // Check existing
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ? OR username = ?'
    ).bind(email.toLowerCase(), username.toLowerCase()).first();

    if (existing) return json({ error: 'Username or email already taken' }, 409);

    const id = genId();
    const salt = genId() + genId();
    const passwordHash = await hashPassword(password, salt);
    const now = Date.now();

    await env.DB.prepare(
      'INSERT INTO users (id, username, email, password_hash, salt, display_name, avatar_emoji, bio, settings, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(id, username.toLowerCase(), email.toLowerCase(), passwordHash, salt, username, '🌱', '', '{}', now).run();

    // Create session
    const sessionId = genId() + genId();
    const expires = now + (30 * 24 * 60 * 60 * 1000);
    await env.DB.prepare(
      'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).bind(sessionId, id, expires, now).run();

    return json(
      { user: { id, username: username.toLowerCase(), email: email.toLowerCase(), display_name: username, avatar_emoji: '🌱', bio: '', settings: '{}' } },
      201,
      { 'Set-Cookie': sessionCookie(sessionId) }
    );
  } catch (err) {
    console.error('Register error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
