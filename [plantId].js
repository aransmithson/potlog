import { hashPassword, genId, json } from '../../_shared/auth.js';

// POST /api/auth/reset — Confirm password reset with token
export async function onRequestPost({ request, env }) {
  try {
    const { token, newPassword } = await request.json();

    if (!token || typeof token !== 'string')
      return json({ error: 'Invalid reset link' }, 400);

    if (!newPassword || newPassword.length < 8)
      return json({ error: 'Password must be at least 8 characters' }, 400);

    if (newPassword.length > 128)
      return json({ error: 'Password is too long' }, 400);

    // Hash the token to match what's stored
    const enc = new TextEncoder();
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(token));
    const tokenHash = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    // Find the reset record
    const reset = await env.DB.prepare(
      'SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?'
    ).bind(tokenHash).first();

    if (!reset)
      return json({ error: 'Invalid or expired reset link' }, 400);

    if (reset.used)
      return json({ error: 'This reset link has already been used' }, 400);

    if (Date.now() > reset.expires_at)
      return json({ error: 'This reset link has expired. Please request a new one.' }, 400);

    // Get user's salt
    const user = await env.DB.prepare('SELECT id, salt FROM users WHERE id = ?')
      .bind(reset.user_id).first();

    if (!user)
      return json({ error: 'User not found' }, 404);

    // Update password
    const newHash = await hashPassword(newPassword, user.salt);
    await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
      .bind(newHash, user.id).run();

    // Mark token as used
    await env.DB.prepare('UPDATE password_resets SET used = 1 WHERE id = ?')
      .bind(reset.id).run();

    // Invalidate all existing sessions (force re-login with new password)
    await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?')
      .bind(user.id).run();

    // Clean up old reset tokens for this user
    await env.DB.prepare('DELETE FROM password_resets WHERE user_id = ? AND (used = 1 OR expires_at < ?)')
      .bind(user.id, Date.now()).run();

    return json({ ok: true, message: 'Password reset successfully. Please sign in with your new password.' });
  } catch (err) {
    console.error('Reset password error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
