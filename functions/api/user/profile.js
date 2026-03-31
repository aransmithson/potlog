import { requireAuth, json } from '../../_shared/auth.js';

export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  return json({ user });
}

export async function onRequestPut({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const body = await request.json();
  const sets = [];
  const vals = [];

  if (body.display_name !== undefined) { sets.push('display_name = ?'); vals.push(body.display_name.trim()); }
  if (body.avatar_emoji !== undefined) { sets.push('avatar_emoji = ?'); vals.push(body.avatar_emoji); }
  if (body.bio !== undefined)          { sets.push('bio = ?');          vals.push(body.bio.trim()); }
  if (body.settings !== undefined)     { sets.push('settings = ?');     vals.push(typeof body.settings === 'string' ? body.settings : JSON.stringify(body.settings)); }

  if (!sets.length) return json({ error: 'Nothing to update' }, 400);

  vals.push(user.id);
  await env.DB.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`)
    .bind(...vals).run();

  const updated = await env.DB.prepare(
    'SELECT id, username, email, display_name, avatar_emoji, bio, settings FROM users WHERE id = ?'
  ).bind(user.id).first();

  return json({ user: updated });
}
