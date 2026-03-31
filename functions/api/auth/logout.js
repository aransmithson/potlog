import { parseCookies, json, clearCookie } from '../../../_shared/auth.js';

export async function onRequestPost({ request, env }) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const token = cookies['pl_session'];

  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
  }

  return json({ ok: true }, 200, { 'Set-Cookie': clearCookie() });
}
