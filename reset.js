import { hashPassword, genId, json, sessionCookie, isValidEmail, LIMITS, checkLoginRateLimit, recordLoginFailure, clearLoginAttempts } from '../../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  try {
    const { email, password } = await request.json();
    if (!email || !password)
      return json({ error: 'Email and password are required' }, 400);

    if (!isValidEmail(email))
      return json({ error: 'Please enter a valid email address' }, 400);

    if (typeof password !== 'string' || password.length > LIMITS.password)
      return json({ error: 'Invalid credentials' }, 401);

    const normEmail = email.toLowerCase();
    const ip = request.headers.get('CF-Connecting-IP') || '';

    // Rate limit: block after 10 failures within a 15-minute sliding window
    if (await checkLoginRateLimit(env.DB, normEmail)) {
      return json({ error: 'Too many failed login attempts. Please try again in 15 minutes.' }, 429);
    }

    const user = await env.DB.prepare(
      'SELECT * FROM users WHERE email = ?'
    ).bind(normEmail).first();

    if (!user) {
      await recordLoginFailure(env.DB, normEmail, ip);
      return json({ error: 'Invalid email or password' }, 401);
    }

    const hash = await hashPassword(password, user.salt);
    if (hash !== user.password_hash) {
      await recordLoginFailure(env.DB, normEmail, ip);
      return json({ error: 'Invalid email or password' }, 401);
    }

    // Successful login — clear the failure counter
    await clearLoginAttempts(env.DB, normEmail);

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
          settings: user.settings,
          role: user.role || 'editor'
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
