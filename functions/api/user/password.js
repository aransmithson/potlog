import { requireAuth, hashPassword, json } from '../../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const { currentPassword, newPassword } = await request.json();
  if (!currentPassword || !newPassword)
    return json({ error: 'Current and new password are required' }, 400);

  if (newPassword.length < 8)
    return json({ error: 'New password must be at least 8 characters' }, 400);

  // Get salt and verify current password
  const row = await env.DB.prepare('SELECT password_hash, salt FROM users WHERE id = ?')
    .bind(user.id).first();

  const currentHash = await hashPassword(currentPassword, row.salt);
  if (currentHash !== row.password_hash)
    return json({ error: 'Current password is incorrect' }, 401);

  // Update password
  const newHash = await hashPassword(newPassword, row.salt);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .bind(newHash, user.id).run();

  // Invalidate all other sessions
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();

  return json({ ok: true });
}
