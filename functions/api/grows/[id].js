import { requireAuth, json, deleteR2Photos, getPlantsList, sanitise, isValidMedium, isValidEnvironment, LIMITS } from '../../_shared/auth.js';

async function ownsGrow(db, userId, growId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  return !!g;
}

// GET /api/grows/:id — Returns plants list for this grow (no notes)
export async function onRequestGet({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const plants = await getPlantsList(env.DB, params.id);
  if (plants === null) return json({ error: 'Not found' }, 404);

  // Also return grow metadata
  const grow = await env.DB.prepare('SELECT * FROM grows WHERE id = ? AND user_id = ?')
    .bind(params.id, user.id).first();

  return json({
    grow: {
      id: grow.id,
      name: grow.name,
      strain: grow.strain || '',
      medium: grow.medium,
      environment: grow.environment,
      completed: !!grow.completed,
      createdAt: grow.created_at,
    },
    plants
  });
}

export async function onRequestPut({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsGrow(env.DB, user.id, params.id))
    return json({ error: 'Not found' }, 404);

  const body = await request.json();
  const sets = [];
  const vals = [];

  if (body.name !== undefined) {
    const name = sanitise(body.name, LIMITS.name);
    if (!name) return json({ error: 'Grow name cannot be empty' }, 400);
    sets.push('name = ?'); vals.push(name);
  }
  if (body.strain !== undefined) {
    sets.push('strain = ?'); vals.push(sanitise(body.strain, LIMITS.strain) || '');
  }
  if (body.medium !== undefined) {
    if (!isValidMedium(body.medium)) return json({ error: 'Invalid growing medium' }, 400);
    sets.push('medium = ?'); vals.push(body.medium);
  }
  if (body.environment !== undefined) {
    if (!isValidEnvironment(body.environment)) return json({ error: 'Invalid environment' }, 400);
    sets.push('environment = ?'); vals.push(body.environment);
  }
  if (body.completed !== undefined) {
    sets.push('completed = ?'); vals.push(body.completed ? 1 : 0);
  }

  if (sets.length) {
    vals.push(params.id);
    await env.DB.prepare(`UPDATE grows SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...vals).run();
  }

  return json({ ok: true });
}

export async function onRequestDelete({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsGrow(env.DB, user.id, params.id))
    return json({ error: 'Not found' }, 404);

  const plants = await env.DB.prepare('SELECT id FROM plants WHERE grow_id = ?')
    .bind(params.id).all();

  for (const plant of plants.results) {
    const notes = await env.DB.prepare('SELECT photo FROM notes WHERE plant_id = ?')
      .bind(plant.id).all();
    const r2Keys = notes.results.map(n => n.photo).filter(Boolean);
    await deleteR2Photos(env.R2, r2Keys);
    await env.DB.prepare('DELETE FROM notes WHERE plant_id = ?').bind(plant.id).run();
  }

  await env.DB.prepare('DELETE FROM plants WHERE grow_id = ?').bind(params.id).run();
  await env.DB.prepare('DELETE FROM grows WHERE id = ?').bind(params.id).run();

  return json({ ok: true });
}
