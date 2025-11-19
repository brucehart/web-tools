import { getSessionUser, requireUser } from './auth';
import { badRequest, json, readJson } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

type Visibility = 'public' | 'unlisted' | 'private';

async function createPaste(
  env: Bindings,
  userId: string,
  title: string,
  content: string,
  visibility: Visibility,
): Promise<Response> {
  if (!content) return badRequest('content required');
  for (let i = 0; i < 5; i++) {
    const slug = visibility === 'public' ? urlSafeRandom(8) : urlSafeRandom(14);
    const exists = await env.DB.prepare('SELECT id FROM pastes WHERE id = ?').bind(slug).first();
    if (exists) continue;
    await env.DB.prepare('INSERT INTO pastes (id, user_id, title, content, visibility) VALUES (?, ?, ?, ?, ?)')
      .bind(slug, userId, title, content, visibility)
      .run();
    return json({ id: slug });
  }
  return badRequest('Failed to allocate id', 500);
}

async function listMine(env: Bindings, userId: string): Promise<Response> {
  const rows = await env.DB.prepare(
    'SELECT id, title, visibility, created_at FROM pastes WHERE user_id = ? ORDER BY created_at DESC LIMIT 200',
  )
    .bind(userId)
    .all();
  return json(rows.results || []);
}

async function listPublic(env: Bindings): Promise<Response> {
  const rows = await env.DB.prepare(
    "SELECT id, title, visibility, created_at FROM pastes WHERE visibility = 'public' ORDER BY created_at DESC LIMIT 200",
  ).all();
  return json(rows.results || []);
}

async function getPaste(request: Request, env: Bindings, id: string): Promise<Response> {
  if (!id) return badRequest('id required');
  const row = (await env.DB.prepare(
    'SELECT id, user_id, title, content, visibility, created_at FROM pastes WHERE id = ?',
  )
    .bind(id)
    .first()) as any;
  if (!row) return new Response('Not found', { status: 404 });
  const me = await getSessionUser(request, env);
  if (row.visibility === 'private') {
    if (!me || me.id !== row.user_id) return new Response('Forbidden', { status: 403 });
  }
  const can_delete = !!(me && me.id === row.user_id);
  const { user_id, ...rest } = row;
  return json({ ...rest, can_delete });
}

async function deletePaste(request: Request, env: Bindings, userId: string): Promise<Response> {
  const body = await readJson<{ id?: string }>(request);
  const id = (body.id || '').toString();
  if (!id) return badRequest('id required');
  const row = (await env.DB.prepare('SELECT user_id FROM pastes WHERE id = ?').bind(id).first()) as any;
  if (!row) return new Response('Not found', { status: 404 });
  if (row.user_id !== userId) return new Response('Forbidden', { status: 403 });
  await env.DB.prepare('DELETE FROM pastes WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

export async function handlePastebinApi(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const path = url.pathname;

  if (path === '/api/pastebin/create' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const body = await readJson<{ title?: string; content?: string; visibility?: Visibility }>(request);
    const content = (body.content || '').toString();
    const title = (body.title || '').toString().slice(0, 200);
    const visibility: Visibility =
      body.visibility === 'unlisted' ? 'unlisted' : body.visibility === 'private' ? 'private' : 'public';
    return createPaste(env, (user as any).id, title, content, visibility);
  }

  if (path === '/api/pastebin/mine' && request.method === 'GET') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return listMine(env, (user as any).id);
  }

  if (path === '/api/pastebin/public' && request.method === 'GET') {
    return listPublic(env);
  }

  if (path === '/api/pastebin/get' && request.method === 'GET') {
    const id = url.searchParams.get('id') || '';
    return getPaste(request, env, id);
  }

  if (path === '/api/pastebin/delete' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return deletePaste(request, env, (user as any).id);
  }

  return null;
}

export async function handlePastebinPage(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const path = url.pathname;
  if (!path.startsWith('/pastebin/p/')) return null;

  const id = path.replace(/^\/pastebin\/p\//, '').replace(/\/$/, '');
  const assetUrl = new URL(url);
  assetUrl.pathname = '/pastebin.html';
  const assetRequest = new Request(assetUrl.toString(), request);
  const assets = (env as any)?.ASSETS;
  let html: string | null = null;
  if (assets && typeof assets.fetch === 'function') {
    const res = await assets.fetch(assetRequest);
    if (res && res.status !== 404) {
      html = await res.text();
    }
  }
  if (!html) {
    const redirectUrl = new URL(request.url);
    redirectUrl.pathname = '/pastebin';
    redirectUrl.search = `?id=${encodeURIComponent(id)}`;
    return Response.redirect(redirectUrl.toString(), 302);
  }
  const injected = html.replace('</body>', `<script>window.PASTE_ID=${JSON.stringify(id)};<\\/script></body>`);
  return new Response(injected, { headers: { 'content-type': 'text/html; charset=utf-8' } });
}
