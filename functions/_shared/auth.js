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
    'SELECT id, username, email, display_name, avatar_emoji, bio, settings, role FROM users WHERE id = ?'
  ).bind(session.user_id).first();
  return user || null;
}

export function isEditor(user) {
  // Default to editor for legacy accounts that may not have a role set
  return user && (user.role === 'editor' || !user.role);
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

// Validation constants
export const LIMITS = {
  name:        100,
  strain:      100,
  note:       2000,
  bio:         500,
  displayName:  50,
  username:     30,
  password:    200,
};

export function isValidEmail(email) {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

export function isValidUsername(username) {
  if (typeof username !== 'string') return false;
  return username.length >= 3 && username.length <= LIMITS.username &&
    /^[a-zA-Z0-9_]+$/.test(username);
}

export function sanitise(str, maxLen) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen || 500);
}

const VALID_MEDIUMS = ['Soil', 'Coco', 'Hydro', 'Aero', 'Other'];
export function isValidMedium(medium) {
  return VALID_MEDIUMS.includes(medium);
}

const VALID_ENVIRONMENTS = ['Indoor', 'Outdoor', 'Greenhouse'];
export function isValidEnvironment(environment) {
  return VALID_ENVIRONMENTS.includes(environment);
}

export async function getGrowsList(db, userId) {
  const growsResult = await db.prepare(
    'SELECT * FROM grows WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(userId).all();
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

export async function getPlantsList(db, growId) {
  const plantsResult = await db.prepare(
    'SELECT * FROM plants WHERE grow_id = ? ORDER BY created_at ASC'
  ).bind(growId).all();
  const plants = [];
  for (const p of plantsResult.results) {
    const noteRow = await db.prepare('SELECT COUNT(*) as cnt FROM notes WHERE plant_id = ?').bind(p.id).first();
    const photoRow = await db.prepare(
      'SELECT photo FROM notes WHERE plant_id = ? AND photo IS NOT NULL ORDER BY timestamp DESC LIMIT 1'
    ).bind(p.id).first();
    plants.push({
      id: p.id, name: p.name, strainOverride: p.strain_override || '',
      stage: p.stage, createdAt: p.created_at,
      milestones: JSON.parse(p.milestones || '[]'),
      dismissedPrompts: JSON.parse(p.dismissed_prompts || '[]'),
      noteCount: noteRow ? noteRow.cnt : 0,
      lastPhoto: photoRow ? photoUrl(photoRow.photo) : null,
    });
  }
  return plants;
}

// R2 helpers
export function photoUrl(stored) {
  if (!stored) return null;
  if (stored.startsWith('data:')) return stored;
  return `/api/photos/${stored}`;
}

export async function deleteR2Photos(r2, keys) {
  for (const key of keys) {
    if (key && !key.startsWith('data:')) {
      try { await r2.delete(key); } catch {}
    }
  }
}

export async function getFullGrows(db, userId) {
  const growsResult = await db.prepare(
    'SELECT * FROM grows WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(userId).all();
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
