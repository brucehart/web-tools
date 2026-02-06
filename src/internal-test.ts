import { json, readJson } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

async function ensureSchema(env: Bindings): Promise<void> {
  // Keep these statements single-purpose; D1 exec instrumentation can be finicky with multi-statement blobs.
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT,
      name TEXT,
      picture TEXT,
      created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      expires_at TEXT
    )
  `).run();
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS tool_pages (
      id TEXT PRIMARY KEY,
      tool TEXT NOT NULL,
      user_id TEXT NOT NULL,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
      updated_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
    )
  `).run();
}

export async function handleInternalTestRoutes(request: Request, env: Bindings, url: URL): Promise<HandlerResult> {
  if (url.pathname !== '/api/_internal/seed') return null;
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  const key = request.headers.get('x-internal-key') || '';
  const expected = (env as any).INTERNAL_TEST_KEY as string | undefined;
  if (!expected || key !== expected) return new Response('Not found', { status: 404 });

  await ensureSchema(env);

  const body = await readJson<{ email?: string; name?: string }>(request);
  const userId = `u_${urlSafeRandom(12)}`;
  const token = `t_${urlSafeRandom(24)}`;
  const email = String(body.email || 'user@example.com');
  const name = String(body.name || 'User');
  await env.DB.prepare('INSERT INTO users (id, email, name, picture) VALUES (?, ?, ?, ?)').bind(userId, email, name, '').run();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, new Date(Date.now() + 60_000).toUTCString())
    .run();

  return json({ userId, token });
}

