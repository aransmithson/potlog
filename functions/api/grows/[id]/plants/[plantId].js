import { requireAuth, json, genId, deleteR2Photos, photoUrl } from '../../../../_shared/auth.js';

async function ownsPlant(db, userId, growId, plantId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  if (!g) return false;
  const p = await db.prepare('SELECT id FROM plants WHERE id = ? AND grow_id = ?')
    .bind(plantId, growId).first();
  return !!p;
}

// GET /api/grows/:id/plants/:plantId — Returns plant details with notes
export async function onRequestGet({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsPlant(env.DB, user.id, params.id, params.plantId))
    return json({ error: 'Not found' }, 404);

  const p = await env.DB.prepare('SELECT * FROM plants WHERE id = ?')
    .bind(params.plantId).first();
  if (!p) return json({ error: 'Not found' }, 404);

  const notesResult = await env.DB.prepare(
    'SELECT * FROM notes WHERE plant_id = ? ORDER BY timestamp ASC'
  ).bind(params.plantId).all();

  return json({
    plant: {
      id: p.id, name: p.name, strainOverride: p.strain_override || '',
      stage: p.stage, createdAt: p.created_at,
      milestones: JSON.parse(p.milestones || '[]'),
      dismissedPrompts: JSON.parse(p.dismissed_prompts || '[]'),
    },
    notes: notesResult.results.map(n => ({
      id: n.id, text: n.text || '', photo: photoUrl(n.photo),
      stage: n.stage, timestamp: n.timestamp
    }))
  });
}

// PUT: update stage, milestones, dismissedPrompts, name
export async function onRequestPut({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsPlant(env.DB, user.id, params.id, params.plantId))
    return json({ error: 'Not found' }, 404);

  const body = await request.json();

  if (body.stage !== undefined) {
    await env.DB.prepare(
      "UPDATE plants SET stage = ?, milestones = '[]' WHERE id = ?"
    ).bind(body.stage, params.plantId).run();

    if (body.stageNote) {
      const noteId = genId();
      await env.DB.prepare(
        'INSERT INTO notes (id, plant_id, text, photo, stage, timestamp) VALUES (?, ?, ?, NULL, ?, ?)'
      ).bind(noteId, params.plantId, body.stageNote, body.stage, Date.now()).run();
    }
  }

  if (body.milestones !== undefined) {
    await env.DB.prepare('UPDATE plants SET milestones = ? WHERE id = ?')
      .bind(JSON.stringify(body.milestones), params.plantId).run();
  }

  if (body.dismissedPrompts !== undefined) {
    await env.DB.prepare('UPDATE plants SET dismissed_prompts = ? WHERE id = ?')
      .bind(JSON.stringify(body.dismissedPrompts), params.plantId).run();
  }

  if (body.name !== undefined) {
    const sets = ['name = ?'];
    const vals = [body.name.trim()];
    if (body.strainOverride !== undefined) {
      sets.push('strain_override = ?');
      vals.push(body.strainOverride);
    }
    vals.push(params.plantId);
    await env.DB.prepare(`UPDATE plants SET ${sets.join(', ')} WHERE id = ?`)
      .bind(...vals).run();
  }

  return json({ ok: true });
}

export async function onRequestDelete({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsPlant(env.DB, user.id, params.id, params.plantId))
    return json({ error: 'Not found' }, 404);

  // Collect and delete R2 photos before removing from D1
  const notes = await env.DB.prepare('SELECT photo FROM notes WHERE plant_id = ?')
    .bind(params.plantId).all();
  const r2Keys = notes.results.map(n => n.photo).filter(Boolean);
  await deleteR2Photos(env.R2, r2Keys);

  await env.DB.prepare('DELETE FROM notes WHERE plant_id = ?').bind(params.plantId).run();
  await env.DB.prepare('DELETE FROM plants WHERE id = ?').bind(params.plantId).run();

  return json({ ok: true });
}
