import { requireUser } from './auth';
import { badRequest, json } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

const HEADER_BLOCKLIST = new Set(['cookie', 'authorization', 'host']);

function safeHeaders(request: Request, url: URL): Record<string, string> {
  const out: Record<string, string> = {};
  request.headers.forEach((value, name) => {
    if (HEADER_BLOCKLIST.has(name.toLowerCase())) return;
    out[name] = value;
  });
  out['x-request-path'] = url.pathname + url.search;
  return out;
}

function safeQuery(url: URL): Record<string, string> {
  const out: Record<string, string> = {};
  url.searchParams.forEach((value, name) => {
    out[name] = value;
  });
  return out;
}

async function readBody(req: Request): Promise<string> {
  const ct = (req.headers.get('content-type') || '').toLowerCase();
  try {
    if (ct.includes('application/json')) {
      const text = await req.text();
      return text;
    }
    const buf = await req.arrayBuffer();
    const bytes = new Uint8Array(buf);
    // Only decode as text when it looks like printable text; otherwise note binary.
    const printable = bytes.every((b) => b === 9 || b === 10 || b === 13 || (b >= 32 && b < 127));
    if (printable) {
      return new TextDecoder().decode(buf).slice(0, 100_000);
    }
    return `[binary body: ${bytes.length} bytes, content-type: ${ct}]`;
  } catch {
    return '';
  }
}

async function createWebhook(env: Bindings, userId: string): Promise<Response> {
  for (let i = 0; i < 5; i++) {
    const id = urlSafeRandom(8);
    const exists = await env.DB.prepare('SELECT id FROM webhooks WHERE id = ?').bind(id).first();
    if (exists) continue;
    await env.DB.prepare('INSERT INTO webhooks (id, user_id) VALUES (?, ?)').bind(id, userId).run();
    return json({ id });
  }
  return badRequest('Failed to allocate id', 500);
}

async function listWebhooks(env: Bindings, userId: string): Promise<Response> {
  const rows = await env.DB.prepare(
    'SELECT id, created_at FROM webhooks WHERE user_id = ? ORDER BY created_at DESC LIMIT 100',
  )
    .bind(userId)
    .all();
  return json(rows.results || []);
}

async function deleteWebhook(env: Bindings, userId: string, id: string): Promise<Response> {
  if (!id) return badRequest('id required');
  const row = await env.DB.prepare('SELECT user_id FROM webhooks WHERE id = ?').bind(id).first();
  if (!row) return new Response('Not found', { status: 404 });
  if (row.user_id !== userId) return new Response('Forbidden', { status: 403 });
  await env.DB.prepare('DELETE FROM webhooks WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function listEvents(env: Bindings, userId: string, id: string, limit = 200): Promise<Response> {
  if (!id) return badRequest('id required');
  const owned = await env.DB.prepare('SELECT user_id FROM webhooks WHERE id = ?').bind(id).first();
  if (!owned) return new Response('Not found', { status: 404 });
  if (owned.user_id !== userId) return new Response('Forbidden', { status: 403 });

  const cap = Math.max(1, Math.min(Number(limit) || 200, 500));
  const rows = (await env.DB.prepare(
    'SELECT id, method, path, headers, query, body, ip, created_at FROM webhook_events WHERE webhook_id = ? ORDER BY rowid DESC LIMIT ?',
  )
    .bind(id, cap)
    .all()) as any;

  const events = (rows.results || []).map((row: any) => ({
    id: row.id,
    method: row.method,
    path: row.path,
    headers: safeParseObject(row.headers),
    query: safeParseObject(row.query),
    body: row.body,
    ip: row.ip,
    created_at: row.created_at,
  }));
  return json(events);
}

function safeParseObject(raw: string): Record<string, string> {
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, string>;
  } catch {
    // ignore
  }
  return {};
}

async function captureEvent(
  env: Bindings,
  userId: string,
  id: string,
  request: Request,
  url: URL,
): Promise<Response> {
  const body = await readBody(request);
  const method = request.method;
  const path = url.pathname;
  const headers = safeHeaders(request, url);
  const query = safeQuery(url);
  const ip = request.headers.get('cf-connecting-ip') || '';

  const eventId = urlSafeRandom(16);
  await env.DB.prepare(
    'INSERT INTO webhook_events (id, webhook_id, method, path, headers, query, body, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(eventId, id, method, path, JSON.stringify(headers), JSON.stringify(query), body, ip)
    .run();

  return json(
    {
      ok: true,
      event_id: eventId,
      message: `Request received at ${new Date().toISOString()}`,
    },
    { status: 200 },
  );
}

export async function handleWebhookApi(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const path = url.pathname;

  if (path === '/api/webhook/create' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return createWebhook(env, (user as any).id);
  }

  if (path === '/api/webhook/list' && request.method === 'GET') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    return listWebhooks(env, (user as any).id);
  }

  if (path === '/api/webhook/delete' && request.method === 'POST') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const body = await (async () => {
      try {
        return await request.json();
      } catch {
        return {};
      }
    })();
    return deleteWebhook(env, (user as any).id, String((body as any).id || ''));
  }

  if (path === '/api/webhook/events' && request.method === 'GET') {
    const user = await requireUser(request, env);
    if (user instanceof Response) return user;
    const id = url.searchParams.get('id') || '';
    const limit = Number(url.searchParams.get('limit')) || 200;
    return listEvents(env, (user as any).id, id, limit);
  }

  return null;
}

// Public capture route: any method to /h/<id>[...] is recorded and returns a JSON receipt.
export async function handleWebhookCapture(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const m = url.pathname.match(/^\/h\/([A-Za-z0-9_-]+)(\/.*)?$/);
  if (!m) return null;
  const id = m[1];
  const row = await env.DB.prepare('SELECT user_id FROM webhooks WHERE id = ?').bind(id).first();
  if (!row) return null; // fall through to 404 static
  return captureEvent(env, (row as any).user_id, id, request, url);
}
