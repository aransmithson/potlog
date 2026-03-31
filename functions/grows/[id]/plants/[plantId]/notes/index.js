import { requireAuth, json, genId } from '../../../../../../_shared/auth.js';

async function ownsPlant(db, userId, growId, plantId) {
  const g = await db.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(growId, userId).first();
  if (!g) return false;
  const p = await db.prepare('SELECT id FROM plants WHERE id = ? AND grow_id = ?')
    .bind(plantId, growId).first();
  return !!p;
}

// Convert a base64 data URI to a Uint8Array
function base64ToBytes(dataUri) {
  const base64 = dataUri.replace(/^data:[^;]+;base64,/, '');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function onRequestPost({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!await ownsPlant(env.DB, user.id, params.id, params.plantId))
    return json({ error: 'Not found' }, 404);

  const { text, photo, stage, timestamp } = await request.json();
  if (!text && !photo) return json({ error: 'Text or photo required' }, 400);

  const id = genId();
  const ts = timestamp || Date.now();

  let storedPhoto = null; // What we save in D1 (R2 key or null)
  let returnPhoto = null; // What we return to the frontend (URL or null)

  if (photo) {
    if (photo.startsWith('data:')) {
      // Upload to R2
      const r2Key = `${user.id}/${id}.jpg`;
      const bytes = base64ToBytes(photo);
      await env.R2.put(r2Key, bytes, {
        httpMetadata: { contentType: 'image/jpeg' }
      });
      storedPhoto = r2Key;
      returnPhoto = `/api/photos/${r2Key}`;
    } else {
      // Already an R2 key (shouldn't happen on POST, but handle gracefully)
      storedPhoto = photo;
      returnPhoto = `/api/photos/${photo}`;
    }
  }

  await env.DB.prepare(
    'INSERT INTO notes (id, plant_id, text, photo, stage, timestamp) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, params.plantId, text || '', storedPhoto, stage || 'germination', ts).run();

  return json({
    note: { id, text: text || '', photo: returnPhoto, stage: stage || 'germination', timestamp: ts }
  }, 201);
}
