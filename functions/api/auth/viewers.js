import { requireAuth, isEditor, genId, json, isValidEmail } from '../../_shared/auth.js';

// GET /api/auth/viewers — list all viewer accounts (editor only)
export async function onRequestGet({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden' }, 403);

  const result = await env.DB.prepare(
    "SELECT id, username, email, display_name, created_at FROM users WHERE role = 'viewer' ORDER BY created_at DESC"
  ).all();

  return json({ viewers: result.results });
}

async function hashToken(rawToken) {
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(rawToken));
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sendInviteEmail({ env, request, email, rawToken, inviterName }) {
  const resendKey = env.RESEND_API_KEY || 're_YEc8JCDW_C2rfoAeXGjzQjPjcP4tW2TNf';
  if (!resendKey) return;

  const fromAddress = env.RESEND_FROM || 'Pot Log <noreply@potlog.app>';
  const origin = new URL(request.url).origin;
  const inviteUrl = `${origin}?invite=${encodeURIComponent(rawToken)}`;

  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${resendKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: fromAddress,
      to: email.toLowerCase(),
      subject: 'You were invited to Pot Log viewer access',
      html: `
        <div style="font-family: -apple-system, sans-serif; max-width: 520px; margin: 0 auto; padding: 32px 20px;">
          <h2 style="color: #10b981; margin-bottom: 16px;">👁️ Pot Log Viewer Invite</h2>
          <p style="color: #333; font-size: 15px; line-height: 1.6;">
            ${inviterName ? `<strong>${inviterName}</strong> invited you` : 'You were invited'} to view shared grows in Pot Log.
          </p>
          <p style="color: #333; font-size: 15px; line-height: 1.6;">
            Click below to create your viewer account. If you already have an account for this email, just sign in and your shared grows will appear on the home screen.
          </p>
          <a href="${inviteUrl}" style="display:inline-block; background:#10b981; color:#fff; text-decoration:none; padding:12px 24px; border-radius:8px; font-weight:600; margin:20px 0;">
            Accept Invite
          </a>
          <p style="color: #888; font-size: 13px;">
            This invite link expires in 7 days.
          </p>
          <p style="color: #888; font-size: 13px;">
            Or paste this link in your browser:<br>
            <a href="${inviteUrl}" style="color:#10b981;">${inviteUrl}</a>
          </p>
        </div>
      `,
    }),
  });
}

// POST /api/auth/viewers — invite a viewer by email (editor only)
export async function onRequestPost({ request, env }) {
  const user = await requireAuth(request, env.DB);
  if (!user) return json({ error: 'Unauthorized' }, 401);
  if (!isEditor(user)) return json({ error: 'Forbidden' }, 403);

  const { email } = await request.json();

  if (!isValidEmail(email))
    return json({ error: 'A valid email address is required' }, 400);

  const normalizedEmail = email.trim().toLowerCase();
  const now = Date.now();
  const expiresAt = now + (7 * 24 * 60 * 60 * 1000);
  const rawToken = genId() + genId() + genId();
  const tokenHash = await hashToken(rawToken);

  // Keep only one active invite per email
  await env.DB.prepare(
    'DELETE FROM viewer_invites WHERE email = ?'
  ).bind(normalizedEmail).run();

  await env.DB.prepare(
    'INSERT INTO viewer_invites (id, email, token_hash, invited_by_user_id, expires_at, used, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)'
  ).bind(genId(), normalizedEmail, tokenHash, user.id, expiresAt, now).run();

  try {
    await sendInviteEmail({
      env,
      request,
      email: normalizedEmail,
      rawToken,
      inviterName: user.display_name || user.username,
    });
  } catch (err) {
    console.error('Viewer invite email error:', err);
    return json({ error: 'Invite created but email sending failed. Please try again.' }, 502);
  }

  return json({
    ok: true,
    message: 'Invite sent.',
    invite: { email: normalizedEmail, expires_at: expiresAt },
  }, 201);
}

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

  // Delete their sessions first
  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(params.id).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(params.id).run();

  return json({ ok: true });
}
