import { requireAllowedUser } from './auth';
import { badRequest, json } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';
import type { StoredValue, WebhookEvent } from './webhook-types';

const HEADER_BLOCKLIST = new Set(['cookie', 'authorization', 'host']);
const WEBHOOK_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const MAX_CAPTURE_BODY_BYTES = 64 * 1024;
const MAX_EVENTS_PER_WEBHOOK = 100;
const MAX_WEBHOOKS_PER_USER = 10;

interface WebhookOwnerRow {
  user_id: string;
}

interface WebhookEventRow {
  id: string;
  method: string;
  path: string;
  headers: string;
  query: string;
  body: string;
  ip: string | null;
  created_at: string;
}

function emptyStoredObject(): Record<string, StoredValue> {
  return Object.create(null) as Record<string, StoredValue>;
}

function serializableStoredObject(value: Record<string, StoredValue>): Record<string, StoredValue> {
  return Object.fromEntries(Object.entries(value));
}

function safeHeaders(request: Request): Record<string, StoredValue> {
  const out = emptyStoredObject();
  request.headers.forEach((value, name) => {
    if (HEADER_BLOCKLIST.has(name.toLowerCase())) return;
    out[name] = value;
  });
  return out;
}

function safeQuery(url: URL): Record<string, StoredValue> {
  const out = emptyStoredObject();
  url.searchParams.forEach((value, name) => {
    const existing = out[name];
    if (existing === undefined) {
      out[name] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      out[name] = [existing, value];
    }
  });
  return out;
}

function decodeBody(bytes: Uint8Array, contentType: string, truncated: boolean): string {
  const truncationNote = truncated ? `\n[body truncated after ${MAX_CAPTURE_BODY_BYTES} bytes]` : '';
  if (bytes.length === 0) return truncationNote.trimStart();

  const textualContentType =
    contentType.startsWith('text/') ||
    /(?:json|xml|javascript|x-www-form-urlencoded|graphql)/.test(contentType);
  if (textualContentType) return new TextDecoder().decode(bytes) + truncationNote;

  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
    const containsBinaryControls = /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text);
    if (!containsBinaryControls) return text + truncationNote;
  } catch {
    // Invalid UTF-8 is represented as binary metadata below.
  }

  const size = truncated ? `more than ${MAX_CAPTURE_BODY_BYTES}` : String(bytes.length);
  return `[binary body: ${size} bytes, content-type: ${contentType || 'unknown'}]`;
}

async function readBody(request: Request): Promise<string> {
  if (!request.body) return '';

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytesRead = 0;
  let truncated = false;

  try {
    while (bytesRead <= MAX_CAPTURE_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.byteLength) continue;

      const remaining = MAX_CAPTURE_BODY_BYTES + 1 - bytesRead;
      const kept = value.subarray(0, remaining);
      chunks.push(kept);
      bytesRead += kept.byteLength;
      if (kept.byteLength < value.byteLength || bytesRead > MAX_CAPTURE_BODY_BYTES) {
        truncated = true;
        break;
      }
    }

    if (truncated) await reader.cancel();
  } catch {
    return '[unable to read request body]';
  }

  const capturedLength = Math.min(bytesRead, MAX_CAPTURE_BODY_BYTES);
  const captured = new Uint8Array(capturedLength);
  let offset = 0;
  for (const chunk of chunks) {
    if (offset >= capturedLength) break;
    const portion = chunk.subarray(0, capturedLength - offset);
    captured.set(portion, offset);
    offset += portion.byteLength;
  }

  const contentType = (request.headers.get('content-type') || '').toLowerCase();
  return decodeBody(captured, contentType, truncated);
}

async function createWebhook(env: Bindings, userId: string): Promise<Response> {
  for (let i = 0; i < 5; i++) {
    const id = urlSafeRandom(16);
    const result = await env.DB.prepare(
      `INSERT OR IGNORE INTO webhooks (id, user_id)
       SELECT ?, ?
       WHERE (SELECT COUNT(*) FROM webhooks WHERE user_id = ?) < ?`,
    )
      .bind(id, userId, userId, MAX_WEBHOOKS_PER_USER)
      .run();
    if (result.meta.changes > 0) return json({ id });

    const count = await env.DB.prepare('SELECT COUNT(*) AS count FROM webhooks WHERE user_id = ?')
      .bind(userId)
      .first<number>('count');
    if ((count || 0) >= MAX_WEBHOOKS_PER_USER) {
      return badRequest(`A maximum of ${MAX_WEBHOOKS_PER_USER} web-hooks is allowed`, 409);
    }
  }
  return badRequest('Failed to allocate id', 500);
}

async function listWebhooks(env: Bindings, userId: string): Promise<Response> {
  const rows = await env.DB.prepare(
    'SELECT id, created_at FROM webhooks WHERE user_id = ? ORDER BY rowid DESC LIMIT ?',
  )
    .bind(userId, MAX_WEBHOOKS_PER_USER)
    .all<{ id: string; created_at: string }>();
  return json(rows.results);
}

async function getWebhookOwner(env: Bindings, id: string): Promise<WebhookOwnerRow | null> {
  return env.DB.prepare('SELECT user_id FROM webhooks WHERE id = ?').bind(id).first<WebhookOwnerRow>();
}

async function requireOwnedWebhook(env: Bindings, userId: string, id: string): Promise<Response | null> {
  if (!WEBHOOK_ID_PATTERN.test(id)) return badRequest('valid id required');
  const row = await getWebhookOwner(env, id);
  if (!row) return new Response('Not found', { status: 404 });
  if (row.user_id !== userId) return new Response('Forbidden', { status: 403 });
  return null;
}

async function deleteWebhook(env: Bindings, userId: string, id: string): Promise<Response> {
  const ownershipError = await requireOwnedWebhook(env, userId, id);
  if (ownershipError) return ownershipError;

  await env.DB.batch([
    env.DB.prepare('DELETE FROM webhook_events WHERE webhook_id = ?').bind(id),
    env.DB.prepare('DELETE FROM webhooks WHERE id = ? AND user_id = ?').bind(id, userId),
  ]);
  return json({ ok: true });
}

async function clearEvents(env: Bindings, userId: string, id: string): Promise<Response> {
  const ownershipError = await requireOwnedWebhook(env, userId, id);
  if (ownershipError) return ownershipError;

  await env.DB.prepare('DELETE FROM webhook_events WHERE webhook_id = ?').bind(id).run();
  return json({ ok: true });
}

async function listEvents(env: Bindings, userId: string, id: string, limit = MAX_EVENTS_PER_WEBHOOK): Promise<Response> {
  const ownershipError = await requireOwnedWebhook(env, userId, id);
  if (ownershipError) return ownershipError;

  const requestedLimit = Number.isFinite(limit) ? Math.trunc(limit) : MAX_EVENTS_PER_WEBHOOK;
  const cap = Math.max(1, Math.min(requestedLimit || MAX_EVENTS_PER_WEBHOOK, MAX_EVENTS_PER_WEBHOOK));
  const rows = await env.DB.prepare(
    'SELECT id, method, path, headers, query, body, ip, created_at FROM webhook_events WHERE webhook_id = ? ORDER BY rowid DESC LIMIT ?',
  )
    .bind(id, cap)
    .all<WebhookEventRow>();

  const events = rows.results.map((row) => ({
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

function safeParseObject(raw: string): WebhookEvent['headers'] {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return emptyStoredObject();

    const out = emptyStoredObject();
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value === 'string') {
        out[key] = value;
      } else if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
        out[key] = value;
      }
    }
    return out;
  } catch {
    return emptyStoredObject();
  }
}

async function captureEvent(
  env: Bindings,
  id: string,
  request: Request,
  url: URL,
): Promise<{ response: Response; event: WebhookEvent }> {
  const body = await readBody(request);
  const method = request.method;
  const path = url.pathname;
  const headers = safeHeaders(request);
  const query = safeQuery(url);
  const ip = request.headers.get('cf-connecting-ip') || '';
  const createdAt = new Date().toISOString();

  const eventId = urlSafeRandom(16);
  await env.DB.batch([
    env.DB.prepare(
      'INSERT INTO webhook_events (id, webhook_id, method, path, headers, query, body, ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ).bind(eventId, id, method, path, JSON.stringify(headers), JSON.stringify(query), body, ip, createdAt),
    env.DB.prepare(
      `DELETE FROM webhook_events
       WHERE webhook_id = ?
         AND rowid NOT IN (
           SELECT rowid FROM webhook_events WHERE webhook_id = ? ORDER BY rowid DESC LIMIT ?
         )`,
    ).bind(id, id, MAX_EVENTS_PER_WEBHOOK),
  ]);

  const event: WebhookEvent = {
    id: eventId,
    method,
    path,
    headers: serializableStoredObject(headers),
    query: serializableStoredObject(query),
    body,
    ip: ip || null,
    created_at: createdAt,
  };
  return {
    event,
    response: json(
      {
        ok: true,
        event_id: eventId,
        message: `Request received at ${event.created_at}`,
      },
      { status: 200 },
    ),
  };
}

async function publishWebhookEvent(env: Bindings, id: string, event: WebhookEvent): Promise<void> {
  await env.WEBHOOK_CONNECTION.getByName(id).publish(event);
}

export async function handleWebhookApi(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const path = url.pathname;

  if (path === '/api/webhook/create' && request.method === 'POST') {
    const user = await requireAllowedUser(request, env);
    if (user instanceof Response) return user;
    return createWebhook(env, user.id);
  }

  if (path === '/api/webhook/list' && request.method === 'GET') {
    const user = await requireAllowedUser(request, env);
    if (user instanceof Response) return user;
    return listWebhooks(env, user.id);
  }

  if (path === '/api/webhook/delete' && request.method === 'POST') {
    const user = await requireAllowedUser(request, env);
    if (user instanceof Response) return user;
    let body: unknown = {};
    try {
      body = await request.json();
    } catch {
      // Invalid JSON is handled as a missing id below.
    }
    const id = body && typeof body === 'object' && 'id' in body ? String(body.id || '') : '';
    return deleteWebhook(env, user.id, id);
  }

  if (path === '/api/webhook/events' && request.method === 'GET') {
    const user = await requireAllowedUser(request, env);
    if (user instanceof Response) return user;
    const id = url.searchParams.get('id') || '';
    const limit = Number(url.searchParams.get('limit') || MAX_EVENTS_PER_WEBHOOK);
    return listEvents(env, user.id, id, limit);
  }

  if (path === '/api/webhook/stream' && request.method === 'GET') {
    const user = await requireAllowedUser(request, env);
    if (user instanceof Response) return user;
    const id = url.searchParams.get('id') || '';
    const ownershipError = await requireOwnedWebhook(env, user.id, id);
    if (ownershipError) return ownershipError;
    return env.WEBHOOK_CONNECTION.getByName(id).fetch(request);
  }

  if (path === '/api/webhook/events' && request.method === 'DELETE') {
    const user = await requireAllowedUser(request, env);
    if (user instanceof Response) return user;
    const id = url.searchParams.get('id') || '';
    return clearEvents(env, user.id, id);
  }

  return null;
}

// Public capture route: any method to /h/<id>[...] is recorded and returns a JSON receipt.
export async function handleWebhookCapture(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const match = url.pathname.match(/^\/h\/([A-Za-z0-9_-]{8,64})(\/.*)?$/);
  if (!match) return null;
  const id = match[1];

  const rateLimit = await env.WEBHOOK_RATE_LIMITER.limit({ key: id });
  if (!rateLimit.success) {
    return new Response('Too many requests', {
      status: 429,
      headers: { 'retry-after': '60' },
    });
  }

  const row = await getWebhookOwner(env, id);
  if (!row) return null; // Fall through to the static 404 response.
  const captured = await captureEvent(env, id, request, url);
  try {
    await publishWebhookEvent(env, id, captured.event);
  } catch (error) {
    // D1 is authoritative; a reconnecting client will catch up if delivery fails.
    console.error('Failed to publish webhook event', { id, error: String(error) });
  }
  return captured.response;
}
