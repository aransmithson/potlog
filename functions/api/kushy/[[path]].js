// Local strain API — serves from bundled dataset (2,351 strains).
// Replaces the old Kushy proxy (api.kushy.net is no longer available).
// Mounted at /api/kushy/...
// Endpoints:
//   GET /api/kushy/strains?limit=100&page=1          → paginated list
//   GET /api/kushy/strains?search=og+kush&limit=8    → search by name
//   GET /api/kushy/strains/:slug                     → single strain by slug

import { STRAINS } from './_strains.js';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', ...CORS_HEADERS },
  });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestGet({ request, params }) {
  const segments = params.path ?? [];
  const url = new URL(request.url);

  // Only handle /strains routes
  if (segments[0] !== 'strains') {
    return json({ error: 'Not found' }, 404);
  }

  // GET /api/kushy/strains/:slug — single strain lookup
  if (segments.length >= 2) {
    const slug = segments.slice(1).join('/').toLowerCase();
    const strain = STRAINS.find(s => s.slug === slug);
    if (!strain) return json({ data: null }, 404);
    return json({ data: strain });
  }

  // GET /api/kushy/strains?search=...&limit=...
  const search = url.searchParams.get('search');
  const limit = Math.min(parseInt(url.searchParams.get('limit')) || 100, 200);
  const page = parseInt(url.searchParams.get('page')) || 1;

  if (search) {
    const q = search.toLowerCase();
    // Find matches, prioritise starts-with over contains
    const startsWith = [];
    const contains = [];
    for (const s of STRAINS) {
      const nameLower = s.name.toLowerCase();
      if (nameLower.startsWith(q)) startsWith.push(s);
      else if (nameLower.includes(q)) contains.push(s);
    }
    startsWith.sort((a, b) => a.name.localeCompare(b.name));
    contains.sort((a, b) => a.name.localeCompare(b.name));
    const results = [...startsWith, ...contains].slice(0, limit);
    return json({ data: results });
  }

  // GET /api/kushy/strains?limit=...&page=... — paginated list
  const offset = (page - 1) * limit;
  const pageData = STRAINS.slice(offset, offset + limit);
  return json({ data: pageData });
}
