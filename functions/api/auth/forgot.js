import { genId, json, isValidEmail } from '../../_shared/auth.js';

// POST /api/auth/forgot — Request a password reset email via Resend
export async function onRequestPost({ request, env }) {
  try {
    const { email } = await request.json();

    if (!isValidEmail(email))
      return json({ error: 'Please enter a valid email address' }, 400);

    // Always return success to prevent email enumeration
    const successMsg = { ok: true, message: 'If that email exists, a reset link has been sent.' };

    const user = await env.DB.prepare(
      'SELECT id, username FROM users WHERE email = ?'
    ).bind(email.toLowerCase()).first();

    if (!user) return json(successMsg);

    // Rate limit: max 3 reset requests per hour per user
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    const recent = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM password_resets WHERE user_id = ? AND created_at > ?'
    ).bind(user.id, oneHourAgo).first();

    if (recent && recent.count >= 3) return json(successMsg);

    // Generate a token (random, URL-safe)
    const rawToken = genId() + genId() + genId();
    // Store a hash of the token (so DB leak doesn't compromise resets)
    const enc = new TextEncoder();
    const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(rawToken));
    const tokenHash = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0')).join('');

    const id = genId();
    const now = Date.now();
    const expiresAt = now + (60 * 60 * 1000); // 1 hour

    await env.DB.prepare(
      'INSERT INTO password_resets (id, user_id, token_hash, expires_at, used, created_at) VALUES (?, ?, ?, ?, 0, ?)'
    ).bind(id, user.id, tokenHash, expiresAt, now).run();

    // Build reset URL
    const origin = new URL(request.url).origin;
    const resetUrl = `${origin}?reset=${rawToken}`;

    // Send email via Resend
    if (env.RESEND_API_KEY) {
      const fromAddress = env.RESEND_FROM || 'Pot Log <noreply@potlog.app>';
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.RESEND_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: fromAddress,
            to: email.toLowerCase(),
            subject: 'Reset your Pot Log password',
            html: `
              <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px 20px;">
                <h2 style="color: #10b981; margin-bottom: 16px;">🌿 Pot Log Password Reset</h2>
                <p style="color: #333; font-size: 15px; line-height: 1.6;">
                  Hi <strong>${user.username}</strong>, we received a request to reset your password.
                </p>
                <p style="color: #333; font-size: 15px; line-height: 1.6;">
                  Click the button below to set a new password. This link expires in 1 hour.
                </p>
                <a href="${resetUrl}" style="display: inline-block; background: #10b981; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600; font-size: 15px; margin: 20px 0;">
                  Reset Password
                </a>
                <p style="color: #888; font-size: 13px; margin-top: 24px;">
                  If you didn't request this, you can safely ignore this email. Your password won't change.
                </p>
                <p style="color: #888; font-size: 13px;">
                  Or paste this link in your browser:<br>
                  <a href="${resetUrl}" style="color: #10b981;">${resetUrl}</a>
                </p>
              </div>
            `,
          }),
        });
      } catch (emailErr) {
        console.error('Resend email error:', emailErr);
        // Don't expose email sending failures to the user
      }
    } else {
      console.warn('RESEND_API_KEY not set — password reset email not sent. Token:', rawToken);
    }

    return json(successMsg);
  } catch (err) {
    console.error('Forgot password error:', err);
    return json({ error: 'Server error' }, 500);
  }
}
