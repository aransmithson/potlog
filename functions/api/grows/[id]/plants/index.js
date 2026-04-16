import { requireAuth, isEditor, json, genId, sanitise, LIMITS, VALID_STAGES } from '../../../../_shared/auth.js';

async function ownsGrow(db, userId, growId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  return !!g;
}

export async function onRequestPost({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden: editor access required' }, 403);
  if (!await ownsGrow(env.DB, user.id, params.id))
    return json({ error: 'Not found' }, 404);

  const { name, strainOverride, stage } = await request.json();

  const cleanName = sanitise(name, LIMITS.name);
  if (!cleanName) return json({ error: 'Plant name is required (max 100 chars)' }, 400);

  const cleanStrain = sanitise(strainOverride, LIMITS.strain);
  const plantStage = VALID_STAGES.includes(stage) ? stage : 'germination';

  const id = genId();
  const now = Date.now();

  await env.DB.prepare(
    'INSERT INTO plants (id, grow_id, name, strain_override, stage, milestones, dismissed_prompts, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, params.id, cleanName, cleanStrain, plantStage, '[]', '[]', now).run();

  return json({
    plant: {
      id, name: cleanName, strainOverride: cleanStrain,
      stage: plantStage, createdAt: now, milestones: [], dismissedPrompts: [], notes: [], photos: []
    }
  }, 201);
}
