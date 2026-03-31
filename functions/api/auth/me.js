import { requireAuth, json } from '../../_shared/auth.js';

export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  return json({ user });
}
