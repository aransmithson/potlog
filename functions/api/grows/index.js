import { requireAuth, json, genId, getGrowsList, getFullGrows, sanitise, isValidMedium, isValidEnvironment, photoUrl, LIMITS } from '../../_shared/auth.js';

// GET /api/grows — Returns grows list with counts (no nested notes)
// All users see grows based on permissions (owned + shared)
// Use ?full=1 for legacy full export
export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const url = new URL(request.url);

  // All users now see grows based on permissions (owned + shared)
  if (url.searchParams.get('full') === '1') {
    const grows = await getFullGrows(env.DB, user.id);
    return json({ grows });
  }
  const grows = await getGrowsList(env.DB, user.id);
  return json({ grows });
}

export async function onRequestPost({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  // Only editors can create new grows
  if (user.role !== 'editor') return json({ error: 'Forbidden: editor access required' }, 403);

  const body = await request.json();
  const name = sanitise(body.name, LIMITS.name);
  if (!name) return json({ error: 'Grow name is required (max 100 chars)' }, 400);

  const strain = sanitise(body.strain, LIMITS.strain) || '';
  const medium = isValidMedium(body.medium) ? body.medium : 'Soil';
  const environment = isValidEnvironment(body.environment) ? body.environment : 'Indoor';

  const id = genId();
  const now = Date.now();

  await env.DB.prepare(
    'INSERT INTO grows (id, user_id, name, strain, medium, environment, completed, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)'
  ).bind(id, user.id, name, strain, medium, environment, now).run();

  return json({
    grow: {
      id, name, strain, medium, environment,
      completed: false, createdAt: now,
      plantCount: 0, noteCount: 0, photoCount: 0,
      permission: 'owner'
    }
  }, 201);
}
