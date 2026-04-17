import { requireAuth, isEditor, json } from '../../../_shared/auth.js';

// DELETE /api/auth/viewers/:id — remove a viewer account (editor only)
export async function onRequestDelete({ request, env, params }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden' }, 403);

  // Confirm the target is actually a viewer (not an editor)
  const target = await env.DB.prepare(
    "SELECT id FROM users WHERE id = ? AND role = 'viewer'"
  ).bind(params.id).first();

  if (!target) return json({ error: 'Viewer not found' }, 404);

  // Delete their sessions first, then the account
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(params.id).run();

  return json({ ok: true });
}
