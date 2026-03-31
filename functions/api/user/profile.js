import { requireAuth, json, sanitise, LIMITS } from '../../_shared/auth.js';

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

  if (body.display_name !== undefined) {
    const dn = sanitise(body.display_name, LIMITS.displayName) || '';
    sets.push('display_name = ?'); vals.push(dn);
  }
  if (body.avatar_emoji !== undefined) {
    const emoji = sanitise(body.avatar_emoji, LIMITS.avatarEmoji) || '🌱';
    sets.push('avatar_emoji = ?'); vals.push(emoji);
  }
  if (body.bio !== undefined) {
    const bio = sanitise(body.bio, LIMITS.bio) || '';
    sets.push('bio = ?'); vals.push(bio);
  }
  if (body.settings !== undefined) {
    const s = typeof body.settings === 'string' ? body.settings : JSON.stringify(body.settings);
    if (s.length > 2000) return json({ error: 'Settings data too large' }, 400);
    sets.push('settings = ?'); vals.push(s);
  }

  if (!sets.length) return json({ error: 'Nothing to update' }, 400);

  vals.push(user.id);
  await env.DB.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`)
    .bind(...vals).run();

  const updated = await env.DB.prepare(
    'SELECT id, username, email, display_name, avatar_emoji, bio, settings FROM users WHERE id = ?'
  ).bind(user.id).first();

  return json({ user: updated });
}
