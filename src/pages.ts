import { requireUser } from './auth';
import { badRequest, json, readJson } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

type Tool = 'markdown' | 'euler';

function parseTool(v: unknown): Tool | null {
  const t = String(v || '').trim().toLowerCase();
  if (t === 'markdown' || t === 'euler') return t;
  return null;
}

function clampTitle(v: unknown): string {
  const s = String(v || '').trim();
  return (s || 'Untitled').slice(0, 200);
}

async function createPage(env: Bindings, userId: string, tool: Tool, title: string, content: string): Promise<Response> {
  for (let i = 0; i < 5; i++) {
    const id = urlSafeRandom(12);
    const exists = await env.DB.prepare('SELECT id FROM tool_pages WHERE id = ?').bind(id).first();
    if (exists) continue;
    await env.DB.prepare('INSERT INTO tool_pages (id, tool, user_id, title, content) VALUES (?, ?, ?, ?, ?)')
      .bind(id, tool, userId, title, content)
      .run();
    return json({ id });
  }
  return badRequest('Failed to allocate id', 500);
}

async function listPages(env: Bindings, userId: string, tool: Tool): Promise<Response> {
  const rows = await env.DB.prepare(
    'SELECT id, title, created_at, updated_at FROM tool_pages WHERE user_id = ? AND tool = ? ORDER BY updated_at DESC LIMIT 200',
  )
    .bind(userId, tool)
    .all();
  return json(rows.results || []);
}

async function getPage(env: Bindings, userId: string, id: string): Promise<Response> {
  if (!id) return badRequest('id required');
  const row = (await env.DB.prepare(
    'SELECT id, tool, title, content, created_at, updated_at FROM tool_pages WHERE id = ? AND user_id = ?',
  )
    .bind(id, userId)
    .first()) as any;
  if (!row) return new Response('Not found', { status: 404 });
  return json(row);
}

async function updatePage(request: Request, env: Bindings, userId: string): Promise<Response> {
  const body = await readJson<{ id?: string; title?: string; content?: string }>(request);
  const id = String(body.id || '').trim();
  if (!id) return badRequest('id required');

  const owned = await env.DB.prepare('SELECT id FROM tool_pages WHERE id = ? AND user_id = ?').bind(id, userId).first();
  if (!owned) return new Response('Not found', { status: 404 });

  const updates: string[] = [];
  const values: any[] = [];
  if (body.title !== undefined) {
    updates.push('title = ?');
    values.push(clampTitle(body.title));
  }
  if (body.content !== undefined) {
    const content = String(body.content || '');
    updates.push('content = ?');
    values.push(content);
  }
  if (updates.length === 0) return badRequest('No fields to update');

  updates.push("updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')");
  values.push(id, userId);
  await env.DB.prepare(`UPDATE tool_pages SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`).bind(...values).run();
  return json({ ok: true });
}

async function deletePage(request: Request, env: Bindings, userId: string): Promise<Response> {
  const body = await readJson<{ id?: string }>(request);
  const id = String(body.id || '').trim();
  if (!id) return badRequest('id required');
  const owned = await env.DB.prepare('SELECT id FROM tool_pages WHERE id = ? AND user_id = ?').bind(id, userId).first();
  if (!owned) return new Response('Not found', { status: 404 });
  await env.DB.prepare('DELETE FROM tool_pages WHERE id = ? AND user_id = ?').bind(id, userId).run();
  return json({ ok: true });
}

export async function handlePagesApi(request: Request, env: Bindings, url: URL): Promise<HandlerResult> {
  const path = url.pathname;

  if (path === '/api/pages/create' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const body = await readJson<{ tool?: string; title?: string; content?: string }>(request);
    const tool = parseTool(body.tool);
    if (!tool) return badRequest('tool must be markdown or euler');
    const title = clampTitle(body.title);
    const content = String(body.content || '');
    return createPage(env, (user as any).id, tool, title, content);
  }

  if (path === '/api/pages/list' && request.method === 'GET') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const tool = parseTool(url.searchParams.get('tool') || '');
    if (!tool) return badRequest('tool must be markdown or euler');
    return listPages(env, (user as any).id, tool);
  }

  if (path === '/api/pages/get' && request.method === 'GET') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const id = url.searchParams.get('id') || '';
    return getPage(env, (user as any).id, id);
  }

  if (path === '/api/pages/update' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return updatePage(request, env, (user as any).id);
  }

  if (path === '/api/pages/delete' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return deletePage(request, env, (user as any).id);
  }

  return null;
}
