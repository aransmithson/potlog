import { hashPassword, genId, json, sessionCookie } from '../../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  try {
    const { email, password } = await request.json();
    if (!email || !password)
      return json({ error: 'Email and password are required' }, 400);

    const user = await env.DB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(email.toLowerCase()).first();

    if (!user) return json({ error: 'Invalid email or password' }, 401);

    const hash = await hashPassword(password, user.salt);
    if (hash !== user.password_hash)
      return json({ error: 'Invalid email or password' }, 401);

    const sessionId = genId() + genId();
    const now = Date.now();
    const expires = now + (30 * 24 * 60 * 60 * 1000);

    await env.DB.prepare(
      'INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
    ).bind(sessionId, user.id, expires, now).run();

    return json(
      {
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          display_name: user.display_name,
          avatar_emoji: user.avatar_emoji,
          bio: user.bio,
          settings: user.settings
        }
      },
      200,
      { 'Set-Cookie': sessionCookie(sessionId) }
    );
  } catch (err) {
    console.error('Login error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
