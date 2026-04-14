import { requireAuth, isEditor } from '../../_shared/auth.js';

export async function onRequestGet({ request, env, params }) {
  // Require a valid session to view any photo
  const user = await requireAuth(request, env.DB);
  if (!user) return new Response('Unauthorized', { status: 401 });

  // params.path is an array of path segments: ['userId', 'noteId.jpg']
  const segments = Array.isArray(params.path) ? params.path : [params.path];
  const r2Key = segments.join('/');

  // Editors can only fetch their own photos; viewers can fetch any
  const ownerId = segments[0];
  if (isEditor(user) && ownerId !== user.id) {
    return new Response('Forbidden', { status: 403 });
  }

  // Fetch from R2
  const obj = await env.R2.get(r2Key);
  if (!obj) return new Response('Not found', { status: 404 });

  const contentType = obj.httpMetadata?.contentType || 'image/jpeg';

  return new Response(obj.body, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'private, max-age=86400',
      'X-Content-Type-Options': 'nosniff'
    }
  });
}
