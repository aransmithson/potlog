import { hashPassword, genId, json, sessionCookie, isValidEmail, isValidUsername, LIMITS } from '../../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  try {
    const { username, email, password } = await request.json();

    if (!username || !email || !password)
      return json({ error: 'Username, email and password are required' }, 400);

    if (!isValidUsername(username))
      return json({ error: 'Username must be 3-30 characters: letters, numbers and underscores only' }, 400);

    if (!isValidEmail(email))
      return json({ error: 'Please enter a valid email address' }, 400);

    if (typeof password !== 'string' || password.length < 8)
      return json({ error: 'Password must be at least 8 characters' }, 400);

    if (password.length > LIMITS.password)
      return json({ error: 'Password is too long' }, 400);

    // Role is always 'editor' for self-registration; use the viewers API to create viewer accounts.
    const userRole = 'editor';

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
      'INSERT INTO users (id, username, email, password_hash, salt, display_name, avatar_emoji, bio, settings, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(id, username.toLowerCase(), email.toLowerCase(), passwordHash, salt, username.slice(0, LIMITS.displayName), '🌱', '', '{}', userRole, now).run();

    // Create session
    const sessionId = genId() + genId();
    const expires = now + (30 * 24 * 60 * 60 * 1000);
    await env.DB.prepare(
      'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).bind(sessionId, id, expires, now).run();

    return json(
      { user: { id, username: username.toLowerCase(), email: email.toLowerCase(), display_name: username.slice(0, LIMITS.displayName), avatar_emoji: '🌱', bio: '', settings: '{}', role: userRole } },
      201,
      { 'Set-Cookie': sessionCookie(sessionId) }
    );
  } catch (err) {
    console.error('Register error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
