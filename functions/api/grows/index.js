import { requireAuth, isEditor, json, genId, getGrowsList, getFullGrows, sanitise, isValidMedium, isValidEnvironment, photoUrl, LIMITS } from '../../_shared/auth.js';

// GET /api/grows — Returns grows list with counts (no nested notes)
// Editors see their own grows; viewers see all grows (single-owner app)
// Use ?full=1 for legacy full export
export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);

  const url = new URL(request.url);

  if (isEditor(user)) {
    if (url.searchParams.get('full') === '1') {
      const grows = await getFullGrows(env.DB, user.id);
      return json({ grows });
    }
    const grows = await getGrowsList(env.DB, user.id);
    return json({ grows });
  } else {
    // Viewer: see all grows in the DB
    if (url.searchParams.get('full') === '1') {
      const grows = await getFullGrowsAll(env.DB);
      return json({ grows });
    }
    const grows = await getGrowsListAll(env.DB);
    return json({ grows });
  }
}

export async function onRequestPost({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden: editor access required' }, 403);

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
      plantCount: 0, noteCount: 0, photoCount: 0
    }
  }, 201);
}

// Helper: list all grows without user_id filter (for viewers)
async function getGrowsListAll(db) {
  const growsResult = await db.prepare(
    'SELECT * FROM grows ORDER BY created_at DESC'
  ).all();
  const grows = [];
  for (const g of growsResult.results) {
    const plantRow = await db.prepare('SELECT COUNT(*) as cnt FROM plants WHERE grow_id = ?').bind(g.id).first();
    const noteRow = await db.prepare('SELECT COUNT(*) as cnt FROM notes n INNER JOIN plants p ON p.id = n.plant_id WHERE p.grow_id = ?').bind(g.id).first();
    const growNoteRow = await db.prepare('SELECT COUNT(*) as cnt FROM grow_notes WHERE grow_id = ?').bind(g.id).first();
    const photoRow = await db.prepare('SELECT COUNT(*) as cnt FROM notes n INNER JOIN plants p ON p.id = n.plant_id WHERE p.grow_id = ? AND n.photo IS NOT NULL').bind(g.id).first();
    grows.push({
      id: g.id, name: g.name, strain: g.strain || '',
      medium: g.medium, environment: g.environment,
      completed: !!g.completed, createdAt: g.created_at,
      plantCount: plantRow ? plantRow.cnt : 0,
      noteCount: (noteRow ? noteRow.cnt : 0) + (growNoteRow ? growNoteRow.cnt : 0),
      photoCount: photoRow ? photoRow.cnt : 0,
    });
  }
  return grows;
}

// Helper: full grows without user_id filter (for viewers)
async function getFullGrowsAll(db) {
  const growsResult = await db.prepare(
    'SELECT * FROM grows ORDER BY created_at DESC'
  ).all();
  const grows = [];
  for (const g of growsResult.results) {
    const plantsResult = await db.prepare('SELECT * FROM plants WHERE grow_id = ? ORDER BY created_at ASC').bind(g.id).all();
    const plants = [];
    for (const p of plantsResult.results) {
      const notesResult = await db.prepare('SELECT * FROM notes WHERE plant_id = ? ORDER BY timestamp ASC').bind(p.id).all();
      plants.push({
        id: p.id, name: p.name, strainOverride: p.strain_override || '',
        stage: p.stage, createdAt: p.created_at,
        milestones: JSON.parse(p.milestones || '[]'),
        dismissedPrompts: JSON.parse(p.dismissed_prompts || '[]'),
        notes: notesResult.results.map(n => ({
          id: n.id, text: n.text || '', photo: photoUrl(n.photo),
          stage: n.stage, timestamp: n.timestamp
        })),
        photos: []
      });
    }
    const growNotesResult = await db.prepare('SELECT * FROM grow_notes WHERE grow_id = ? ORDER BY timestamp ASC').bind(g.id).all();
    grows.push({
      id: g.id, name: g.name, strain: g.strain || '',
      medium: g.medium, environment: g.environment,
      completed: !!g.completed, createdAt: g.created_at,
      plants,
      notes: growNotesResult.results.map(n => ({
        id: n.id, text: n.text || '', photo: photoUrl(n.photo), timestamp: n.timestamp
      }))
    });
  }
  return grows;
}
