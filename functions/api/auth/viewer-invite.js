import { json } from '../../_shared/auth.js';

async function hashToken(rawToken) {
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(rawToken));
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

// GET /api/auth/viewer-invite?token=... — validate a viewer invite token
export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) return json({ error: 'Invite token is required' }, 400);

  const tokenHash = await hashToken(token);
  const invite = await env.DB.prepare(
    'SELECT email, expires_at, used FROM viewer_invites WHERE token_hash = ?'
  ).bind(tokenHash).first();

  if (!invite || invite.used || Date.now() > invite.expires_at) {
    return json({ error: 'Invite is invalid or expired' }, 400);
  }

  return json({
    ok: true,
    email: invite.email,
    expires_at: invite.expires_at,
  });
}
