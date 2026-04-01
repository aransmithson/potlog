// Kushy API proxy — forwards requests to api.kushy.net server-side,
// avoiding CORS restrictions in the browser.
// Mounted at /api/kushy/...
// e.g. GET /api/kushy/strains?search=og&limit=8  →  api.kushy.net/api/strains?search=og&limit=8
//      GET /api/kushy/strains/northern-lights     →  api.kushy.net/api/strains/northern-lights

const KUSHY_ORIGIN = 'https://api.kushy.net/api';
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function onRequestGet({ request, params }) {
  // params.path is an array of path segments after /api/kushy/
  const segments = params.path ?? [];
  const upstreamPath = segments.join('/');

  // Forward query string unchanged
  const incomingUrl = new URL(request.url);
  const upstreamUrl = `${KUSHY_ORIGIN}/${upstreamPath}${incomingUrl.search}`;

  let upstreamRes;
  try {
    upstreamRes = await fetch(upstreamUrl, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'PotLog/1.0' },
      cf: { cacheTtl: 300, cacheEverything: true }, // cache at Cloudflare edge for 5 min
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Kushy API unreachable', detail: err.message }), {
      status: 502,
      headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
    });
  }

  // Pass through status and body, adding CORS headers
  const body = await upstreamRes.text();
  return new Response(body, {
    status: upstreamRes.status,
    headers: {
      'Content-Type': upstreamRes.headers.get('Content-Type') || 'application/json',
      'Cache-Control': 'public, max-age=300',
      ...CORS_HEADERS,
    },
  });
}
