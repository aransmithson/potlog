import { requireAuth, json, deleteR2Photos } from '../../_shared/auth.js';

async function ownsGrow(db, userId, growId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  return !!g;
}

export async function onRequestPut({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsGrow(env.DB, user.id, params.id))
    return json({ error: 'Not found' }, 404);

  const body = await request.json();
  const sets = [];
  const vals = [];

  if (body.name !== undefined)        { sets.push('name = ?');        vals.push(body.name.trim()); }
  if (body.strain !== undefined)      { sets.push('strain = ?');      vals.push(body.strain); }
  if (body.medium !== undefined)      { sets.push('medium = ?');      vals.push(body.medium); }
  if (body.environment !== undefined) { sets.push('environment = ?'); vals.push(body.environment); }
  if (body.completed !== undefined)   { sets.push('completed = ?');   vals.push(body.completed ? 1 : 0); }

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

  // Collect all R2 keys before deleting from D1
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
