import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

async function seedUser(env: any, email: string): Promise<string> {
  (env as any).INTERNAL_TEST_KEY = 'k';
  const request = new IncomingRequest('http://example.com/api/_internal/seed', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-internal-key': 'k' },
    body: JSON.stringify({ email, name: email }),
  });
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  expect(response.status).toBe(200);
  const seeded = await response.json<any>();
  return String(seeded.token || '');
}

async function createHook(env: any, token: string): Promise<string> {
  const request = new IncomingRequest('http://example.com/api/webhook/create', {
    method: 'POST',
    headers: { cookie: `wt_session=${token}` },
  });
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, env, ctx);
  await waitOnExecutionContext(ctx);
  expect(response.status).toBe(200);
  const body = await response.json<any>();
  return String(body.id || '');
}

describe('WebHook Tester', () => {
  it('serves web-hook page at /web-hook (unit)', async () => {
    const request = new IncomingRequest('http://example.com/web-hook');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>WebHook Tester</title>');
    expect(body).toContain('id="createBtn"');
    expect(body).toContain('id="events"');
  });

  it('serves web-hook page (integration)', async () => {
    const response = await SELF.fetch('https://example.com/web-hook');
    expect(response.status).toBe(200);
    const body = await response.text();
    expect(body).toContain('<title>WebHook Tester</title>');
  });

  it('requires auth to create a web-hook', async () => {
    const request = new IncomingRequest('http://example.com/api/webhook/create', { method: 'POST' });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(401);
  });

  it('requires auth to open a web-hook stream', async () => {
    const request = new IncomingRequest('http://example.com/api/webhook/stream?id=missing', {
      headers: { upgrade: 'websocket' },
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(401);
  });

  it('restricts web-hook management to the allowed Google account', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const token = await seedUser(env, 'not-authorized@example.com');
    const request = new IncomingRequest('http://example.com/api/webhook/create', {
      method: 'POST',
      headers: { cookie: `wt_session=${token}` },
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(403);
  });

  it('opens an authenticated stream for the webhook owner', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, token);
    const request = new IncomingRequest(`http://example.com/api/webhook/stream?id=${id}`, {
      headers: { cookie: `wt_session=${token}`, upgrade: 'websocket' },
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(101);
    const socket = response.webSocket;
    expect(socket).toBeDefined();
    socket?.accept();
    const notification = new Promise<string>((resolve) => {
      socket?.addEventListener('message', (event) => resolve(String((event as MessageEvent).data)), { once: true });
    });
    const postCtx = createExecutionContext();
    const postResponse = await worker.fetch(new IncomingRequest(`http://example.com/h/${id}/payload`, { method: 'POST' }), env, postCtx);
    await waitOnExecutionContext(postCtx);
    expect(postResponse.status).toBe(200);
    const message = JSON.parse(await notification);
    expect(message.type).toBe('event');
    expect(message.event.path).toBe(`/h/${id}/payload`);
    socket?.close();
  });

  it('creates a web-hook, captures a request, and lists events (unit)', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, token);

    // Capture a POST with headers, query params, and a JSON body.
    const post = new IncomingRequest(`http://example.com/h/${id}/payload?foo=bar&x=1`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-custom': 'custom-value',
        'user-agent': 'webhook-test/1.0',
      },
      body: JSON.stringify({ hello: 'world' }),
    });
    const postCtx = createExecutionContext();
    const postRes = await worker.fetch(post, env, postCtx);
    await waitOnExecutionContext(postCtx);
    expect(postRes.status).toBe(200);
    const receipt = await postRes.json<any>();
    expect(receipt.ok).toBe(true);
    expect(receipt.event_id).toBeTruthy();

    // Capture a GET too.
    const get = new IncomingRequest(`http://example.com/h/${id}/hooks/created`, { method: 'GET' });
    const getCtx = createExecutionContext();
    const getRes = await worker.fetch(get, env, getCtx);
    await waitOnExecutionContext(getCtx);
    expect(getRes.status).toBe(200);

    // List events for the owner.
    const list = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      headers: { cookie: `wt_session=${token}` },
    });
    const listCtx = createExecutionContext();
    const listRes = await worker.fetch(list, env, listCtx);
    await waitOnExecutionContext(listCtx);
    expect(listRes.status).toBe(200);
    const events = await listRes.json<any[]>();
    expect(events.length).toBe(2);

    const postEv = events.find((ev) => ev.method === 'POST');
    const getEv = events.find((ev) => ev.method === 'GET');
    expect(postEv).toBeTruthy();
    expect(getEv).toBeTruthy();
    // Newest first.
    expect(events[0].method).toBe('GET');
    expect(events[1].method).toBe('POST');

    expect(postEv.path).toBe(`/h/${id}/payload`);
    expect(postEv.headers['content-type']).toContain('application/json');
    expect(postEv.headers['x-custom']).toBe('custom-value');
    // Authentication- and host-related headers are not leaked back to the UI.
    expect(postEv.headers['authorization']).toBeUndefined();
    expect(postEv.headers['cookie']).toBeUndefined();
    expect(postEv.headers['host']).toBeUndefined();
    expect(postEv.query).toEqual({ foo: 'bar', x: '1' });
    expect(postEv.body).toContain('"hello"');
  });

  it('preserves duplicate query values and bounds Unicode body capture', async () => {
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, token);
    const unicodeBody = 'こんにちは'.repeat(20_000);

    const capture = new IncomingRequest(`http://example.com/h/${id}/payload?tag=one&tag=two`, {
      method: 'POST',
      headers: { 'content-type': 'text/plain; charset=utf-8' },
      body: unicodeBody,
    });
    const captureCtx = createExecutionContext();
    const captureRes = await worker.fetch(capture, env, captureCtx);
    await waitOnExecutionContext(captureCtx);
    expect(captureRes.status).toBe(200);

    const list = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      headers: { cookie: `wt_session=${token}` },
    });
    const listCtx = createExecutionContext();
    const listRes = await worker.fetch(list, env, listCtx);
    await waitOnExecutionContext(listCtx);
    const events = await listRes.json<any[]>();

    expect(events).toHaveLength(1);
    expect(events[0].query).toEqual({ tag: ['one', 'two'] });
    expect(events[0].body).toContain('こんにちは');
    expect(events[0].body).toContain('[body truncated after 65536 bytes]');
    expect(new TextEncoder().encode(events[0].body).byteLength).toBeLessThan(66_000);
  });

  it('clears captured events permanently for the owner', async () => {
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, token);

    const captureRes = await SELF.fetch(`http://example.com/h/${id}`, { method: 'POST', body: 'event' });
    expect(captureRes.status).toBe(200);

    const clear = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      method: 'DELETE',
      headers: { cookie: `wt_session=${token}` },
    });
    const clearCtx = createExecutionContext();
    const clearRes = await worker.fetch(clear, env, clearCtx);
    await waitOnExecutionContext(clearCtx);
    expect(clearRes.status).toBe(200);

    const list = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      headers: { cookie: `wt_session=${token}` },
    });
    const listCtx = createExecutionContext();
    const listRes = await worker.fetch(list, env, listCtx);
    await waitOnExecutionContext(listCtx);
    expect(await listRes.json<any[]>()).toEqual([]);
  });

  it('retains only the newest 100 events per web-hook', async () => {
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, token);
    const statements = Array.from({ length: 100 }, (_, index) =>
      env.DB.prepare(
        'INSERT INTO webhook_events (id, webhook_id, method, path, headers, query, body, ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ).bind(`seed-event-${index}`, id, 'POST', `/seed/${index}`, '{}', '{}', String(index), ''),
    );
    await env.DB.batch(statements);

    const captureRes = await SELF.fetch(`http://example.com/h/${id}/newest`, { method: 'POST', body: 'newest' });
    expect(captureRes.status).toBe(200);

    const list = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}&limit=500`, {
      headers: { cookie: `wt_session=${token}` },
    });
    const listCtx = createExecutionContext();
    const listRes = await worker.fetch(list, env, listCtx);
    await waitOnExecutionContext(listCtx);
    const events = await listRes.json<any[]>();

    expect(events).toHaveLength(100);
    expect(events[0].path).toBe(`/h/${id}/newest`);
    expect(events.some((event) => event.id === 'seed-event-0')).toBe(false);
  });

  it('does not list events for a non-owner', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const ownerToken = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, ownerToken);
    const otherToken = await seedUser(env, 'bruce.hart@gmail.com');

    const list = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      headers: { cookie: `wt_session=${otherToken}` },
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(list, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(403);

    const clear = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      method: 'DELETE',
      headers: { cookie: `wt_session=${otherToken}` },
    });
    const clearCtx = createExecutionContext();
    const clearResponse = await worker.fetch(clear, env, clearCtx);
    await waitOnExecutionContext(clearCtx);
    expect(clearResponse.status).toBe(403);
  });

  it('limits each account to 10 web-hooks', async () => {
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    for (let index = 0; index < 10; index++) await createHook(env, token);

    const request = new IncomingRequest('http://example.com/api/webhook/create', {
      method: 'POST',
      headers: { cookie: `wt_session=${token}` },
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(409);
    expect(await response.text()).toContain('maximum of 10');
  });

  it('owner can delete a web-hook', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const token = await seedUser(env, 'bruce.hart@gmail.com');
    const id = await createHook(env, token);

    const del = new IncomingRequest('http://example.com/api/webhook/delete', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${token}` },
      body: JSON.stringify({ id }),
    });
    const delCtx = createExecutionContext();
    const delRes = await worker.fetch(del, env, delCtx);
    await waitOnExecutionContext(delCtx);
    expect(delRes.status).toBe(200);
    expect(await delRes.json<any>()).toEqual({ ok: true });

    const storedEvents = await env.DB.prepare('SELECT COUNT(*) AS count FROM webhook_events WHERE webhook_id = ?')
      .bind(id)
      .first<number>('count');
    expect(storedEvents).toBe(0);

    const afterPost = new IncomingRequest(`http://example.com/h/${id}/after-delete`, { method: 'POST' });
    const afterCtx = createExecutionContext();
    const afterRes = await worker.fetch(afterPost, env, afterCtx);
    await waitOnExecutionContext(afterCtx);
    expect(afterRes.status).toBe(404);
  });
});
