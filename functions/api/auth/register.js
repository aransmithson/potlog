import { hashPassword, genId, json, sessionCookie, isValidEmail, isValidUsername, LIMITS } from '../../_shared/auth.js';

async function hashToken(rawToken) {
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(rawToken));
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function onRequestPost({ request, env }) {
  try {
    const { username, email, password, inviteToken } = await request.json();

    if (!username || !password)
      return json({ error: 'Username and password are required' }, 400);

    if (!isValidUsername(username))
      return json({ error: 'Username must be 3-30 characters: letters, numbers and underscores only' }, 400);

    if (typeof password !== 'string' || password.length < 8)
      return json({ error: 'Password must be at least 8 characters' }, 400);

    if (password.length > LIMITS.password)
      return json({ error: 'Password is too long' }, 400);

    const normalizedUsername = username.toLowerCase();
    let normalizedEmail = (email || '').toLowerCase().trim();
    let userRole = 'editor';
    let inviteRecord = null;

    if (inviteToken) {
      const tokenHash = await hashToken(inviteToken);
      inviteRecord = await env.DB.prepare(
        'SELECT id, email, expires_at, used FROM viewer_invites WHERE token_hash = ?'
      ).bind(tokenHash).first();

      if (!inviteRecord || inviteRecord.used || Date.now() > inviteRecord.expires_at) {
        return json({ error: 'This viewer invite is invalid or expired.' }, 400);
      }

      normalizedEmail = inviteRecord.email.toLowerCase();
      userRole = 'viewer';
    } else {
      if (!isValidEmail(email))
        return json({ error: 'Please enter a valid email address' }, 400);
    }

    // Check existing
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ? OR username = ?'
    ).bind(normalizedEmail, normalizedUsername).first();

    if (existing) {
      if (inviteRecord) {
        await env.DB.prepare('UPDATE viewer_invites SET used = 1 WHERE id = ?').bind(inviteRecord.id).run();
        return json({ error: 'An account for this email already exists. Please sign in instead.' }, 409);
      }
      return json({ error: 'Username or email already taken' }, 409);
    }

    const id = genId();
    const salt = genId() + genId();
    const passwordHash = await hashPassword(password, salt);
    const now = Date.now();

    await env.DB.prepare(
      'INSERT INTO users (id, username, email, password_hash, salt, display_name, avatar_emoji, bio, settings, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(id, normalizedUsername, normalizedEmail, passwordHash, salt, username.slice(0, LIMITS.displayName), userRole === 'viewer' ? '👁️' : '🌱', '', '{}', userRole, now).run();

    if (inviteRecord) {
      await env.DB.prepare('UPDATE viewer_invites SET used = 1 WHERE id = ?').bind(inviteRecord.id).run();
      await env.DB.prepare(
        'DELETE FROM viewer_invites WHERE email = ? AND used = 0'
      ).bind(normalizedEmail).run();
    }

    // Create session
    const sessionId = genId() + genId();
    const expires = now + (30 * 24 * 60 * 60 * 1000);
    await env.DB.prepare(
      'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).bind(sessionId, id, expires, now).run();

    return json(
      { user: { id, username: normalizedUsername, email: normalizedEmail, display_name: username.slice(0, LIMITS.displayName), avatar_emoji: userRole === 'viewer' ? '👁️' : '🌱', bio: '', settings: '{}', role: userRole } },
      201,
      { 'Set-Cookie': sessionCookie(sessionId) }
    );
  } catch (err) {
    console.error('Register error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
