// Shared auth utilities for Pot Log Pages Functions

export async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return Array.from(new Uint8Array(bits))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

export function genId() {
  return crypto.randomUUID().replace(/-/g, '');
}

export function parseCookies(header) {
  if (!header) return {};
  const result = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    try { result[k] = decodeURIComponent(v); } catch { result[k] = v; }
  }
  return result;
}

export async function requireAuth(request, db) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const token = cookies['pl_session'];
  if (!token) return null;

  const session = await db.prepare(
    'SELECT user_id FROM sessions WHERE id = ? AND expires_at > ?'
  ).bind(token, Date.now()).first();
  if (!session) return null;

  const user = await db.prepare(
    'SELECT id, username, email, display_name, avatar_emoji, bio, settings FROM users WHERE id = ?'
  ).bind(session.user_id).first();
  return user || null;
}

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}

export function sessionCookie(token) {
  const maxAge = 30 * 24 * 60 * 60; // 30 days
  return `pl_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

export function clearCookie() {
  return 'pl_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0';
}

// R2 helpers
// Convert stored photo value to a URL the frontend can use.
// Stored value is either:
//   - an R2 key  (e.g. "userId/noteId.jpg")  → serve via /api/photos/...
//   - a legacy base64 data URI               → return as-is
export function photoUrl(stored) {
  if (!stored) return null;
  if (stored.startsWith('data:')) return stored; // legacy
  return `/api/photos/${stored}`;
}

// Delete one or more R2 objects by their stored keys (ignores base64 values)
export async function deleteR2Photos(r2, keys) {
  for (const key of keys) {
    if (key && !key.startsWith('data:')) {
      try { await r2.delete(key); } catch {}
    }
  }
}

// Assemble full data structure from D1 tables (matching localStorage format)
export async function getFullGrows(db, userId) {
  const growsResult = await db.prepare(
    'SELECT * FROM grows WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(userId).all();

  const grows = [];
  for (const g of growsResult.results) {
    const plantsResult = await db.prepare(
      'SELECT * FROM plants WHERE grow_id = ? ORDER BY created_at ASC'
    ).bind(g.id).all();

    const plants = [];
    for (const p of plantsResult.results) {
      const notesResult = await db.prepare(
        'SELECT * FROM notes WHERE plant_id = ? ORDER BY timestamp ASC'
      ).bind(p.id).all();

      plants.push({
        id: p.id,
        name: p.name,
        strainOverride: p.strain_override || '',
        stage: p.stage,
        createdAt: p.created_at,
        milestones: JSON.parse(p.milestones || '[]'),
        dismissedPrompts: JSON.parse(p.dismissed_prompts || '[]'),
        notes: notesResult.results.map(n => ({
          id: n.id,
          text: n.text || '',
          photo: photoUrl(n.photo),
          stage: n.stage,
          timestamp: n.timestamp
        })),
        photos: []
      });
    }

    grows.push({
      id: g.id,
      name: g.name,
      strain: g.strain || '',
      medium: g.medium,
      environment: g.environment,
      completed: !!g.completed,
      createdAt: g.created_at,
      plants
    });
  }
  return grows;
}
