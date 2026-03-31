import { requireAuth } from '../../_shared/auth.js';

export async function onRequestGet({ request, env, params }) {
  // Require a valid session to view any photo
  const user = await requireAuth(request, env.DB);
  if (!user) return new Response('Unauthorized', { status: 401 });

  // params.path is an array of path segments: ['userId', 'noteId.jpg']
  const segments = Array.isArray(params.path) ? params.path : [params.path];
  const r2Key = segments.join('/');

  // The first segment is the owner's user ID — enforce it matches the session
  const ownerId = segments[0];
  if (ownerId !== user.id) {
    return new Response('Forbidden', { status: 403 });
  }

  // Fetch from R2
  const obj = await env.R2.get(r2Key);
  if (!obj) return new Response('Not found', { status: 404 });

  const contentType = obj.httpMetadata?.contentType || 'image/jpeg';

  return new Response(obj.body, {
    headers: {
      'Content-Type': contentType,
      // Cache in the browser for 24 h (private — not shared/CDN cacheable)
      'Cache-Control': 'private, max-age=86400',
      // Prevent content sniffing
      'X-Content-Type-Options': 'nosniff'
    }
  });
}
