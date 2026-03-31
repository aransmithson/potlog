import { requireAuth, json, genId } from '../../../../_shared/auth.js';

async function ownsGrow(db, userId, growId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  return !!g;
}

export async function onRequestPost({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsGrow(env.DB, user.id, params.id))
    return json({ error: 'Not found' }, 404);

  const { name, strainOverride, stage } = await request.json();
  if (!name) return json({ error: 'Plant name is required' }, 400);

  const id = genId();
  const now = Date.now();
  const plantStage = stage || 'germination';

  await env.DB.prepare(
    'INSERT INTO plants (id, grow_id, name, strain_override, stage, milestones, dismissed_prompts, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, params.id, name.trim(), strainOverride || '', plantStage, '[]', '[]', now).run();

  return json({
    plant: {
      id, name: name.trim(), strainOverride: strainOverride || '',
      stage: plantStage, createdAt: now, milestones: [], dismissedPrompts: [], notes: [], photos: []
    }
  }, 201);
}
