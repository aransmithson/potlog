import { requireAuth, json, deleteR2Photos, getPlantsList, sanitise, isValidMedium, isValidEnvironment, LIMITS, canEditGrow } from '../../_shared/auth.js';

// Check if user owns a grow
async function ownsGrow(db, userId, growId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  return !!g;
}

// GET /api/grows/:id — Returns plants list for this grow (no notes)
export async function onRequestGet({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  // Check if user has permission to view this grow
  const hasPermission = await ownsGrow(env.DB, user.id, params.id) || 
    await canViewGrow(env.DB, user.id, params.id);
  if (!hasPermission) return json({ error: 'Not found' }, 404);

  const plants = await getPlantsList(env.DB, params.id);
  if (plants === null) return json({ error: 'Not found' }, 404);

  const grow = await env.DB.prepare('SELECT * FROM grows WHERE id = ?').bind(params.id).first();
  if (!grow) return json({ error: 'Not found' }, 404);

  // Determine user's permission level
  let permission = 'owner';
  if (!await ownsGrow(env.DB, user.id, params.id)) {
    const permRow = await env.DB.prepare(
      'SELECT permission FROM grow_permissions WHERE grow_id = ? AND user_id = ?'
    ).bind(params.id, user.id).first();
    permission = permRow?.permission || 'view';
  }

  return json({
    grow: {
      id: grow.id,
      name: grow.name,
      strain: grow.strain || '',
      medium: grow.medium,
      environment: grow.environment,
      completed: !!grow.completed,
      createdAt: grow.created_at,
      permission,
    },
    plants
  });
}

export async function onRequestPut({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  
  // Check if user has edit permission (owner or shared with edit permission)
  const canEdit = await canEditGrow(env.DB, user.id, params.id);
  if (!canEdit) return json({ error: 'Forbidden: edit access required' }, 403);

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
  if (!isEditor(user)) return json({ error: 'Forbidden: editor access required' }, 403);
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
  await env.DB.prepare('DELETE FROM grow_notes WHERE grow_id = ?').bind(params.id).run();
  await env.DB.prepare('DELETE FROM grows WHERE id = ?').bind(params.id).run();

  return json({ ok: true });
}
