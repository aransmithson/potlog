import { requireAuth, isEditor, json } from '../../../../../../_shared/auth.js';

export async function onRequestDelete({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden: editor access required' }, 403);

  // Verify ownership chain
  const g = await env.DB.prepare('SELECT id FROM grows WHERE id = ? AND user_id = ?')
    .bind(params.id, user.id).first();
  if (!g) return json({ error: 'Not found' }, 404);

  // Fetch the note first so we can delete its R2 object
  const note = await env.DB.prepare(
    'SELECT photo FROM notes WHERE id = ? AND plant_id = ?'
  ).bind(params.noteId, params.plantId).first();

  // Delete from D1
  await env.DB.prepare('DELETE FROM notes WHERE id = ? AND plant_id = ?')
    .bind(params.noteId, params.plantId).run();

  // Delete from R2 if there's a stored key (not a legacy base64 value)
  if (note?.photo && !note.photo.startsWith('data:')) {
    try { await env.R2.delete(note.photo); } catch {}
  }

  return json({ ok: true });
}
