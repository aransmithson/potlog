import { requireAuth, json, genId, getFullGrows } from '../../_shared/auth.js';

export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const grows = await getFullGrows(env.DB, user.id);
  return json({ grows });
}

export async function onRequestPost({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const { name, strain, medium, environment } = await request.json();
  if (!name) return json({ error: 'Grow name is required' }, 400);

  const id = genId();
  const now = Date.now();

  await env.DB.prepare(
    'INSERT INTO grows (id, user_id, name, strain, medium, environment, completed, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)'
  ).bind(id, user.id, name.trim(), strain || '', medium || 'Soil', environment || 'Indoor', now).run();

  return json({
    grow: {
      id, name: name.trim(), strain: strain || '', medium: medium || 'Soil',
      environment: environment || 'Indoor', completed: false, createdAt: now, plants: []
    }
  }, 201);
}
