import { requireAuth, hashPassword, json, clearCookie, deleteR2Photos } from '../../_shared/auth.js';

export async function onRequestDelete({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const { password } = await request.json();
  if (!password) return json({ error: 'Password required to delete account' }, 400);

  const row = await env.DB.prepare('SELECT password_hash, salt FROM users WHERE id = ?')
    .bind(user.id).first();

  const hash = await hashPassword(password, row.salt);
  if (hash !== row.password_hash)
    return json({ error: 'Incorrect password' }, 401);

  // Collect all R2 keys, then cascade delete everything
  const grows = await env.DB.prepare('SELECT id FROM grows WHERE user_id = ?').bind(user.id).all();

  for (const g of grows.results) {
    const plants = await env.DB.prepare('SELECT id FROM plants WHERE grow_id = ?').bind(g.id).all();
    for (const p of plants.results) {
      const notes = await env.DB.prepare('SELECT photo FROM notes WHERE plant_id = ?').bind(p.id).all();
      const r2Keys = notes.results.map(n => n.photo).filter(Boolean);
      await deleteR2Photos(env.R2, r2Keys);
      await env.DB.prepare('DELETE FROM notes WHERE plant_id = ?').bind(p.id).run();
    }
    await env.DB.prepare('DELETE FROM plants WHERE grow_id = ?').bind(g.id).run();
  }

  await env.DB.prepare('DELETE FROM grows WHERE user_id = ?').bind(user.id).run();
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();

  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}
