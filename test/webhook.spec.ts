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

  it('creates a web-hook, captures a request, and lists events (unit)', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const token = await seedUser(env, 'webhook-owner@example.com');
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

  it('does not list events for a non-owner', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const ownerToken = await seedUser(env, 'webhook-owner2@example.com');
    const id = await createHook(env, ownerToken);
    const otherToken = await seedUser(env, 'webhook-other@example.com');

    const list = new IncomingRequest(`http://example.com/api/webhook/events?id=${id}`, {
      headers: { cookie: `wt_session=${otherToken}` },
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(list, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(403);
  });

  it('owner can delete a web-hook', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const token = await seedUser(env, 'webhook-delete@example.com');
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

    const afterPost = new IncomingRequest(`http://example.com/h/${id}/after-delete`, { method: 'POST' });
    const afterCtx = createExecutionContext();
    const afterRes = await worker.fetch(afterPost, env, afterCtx);
    await waitOnExecutionContext(afterCtx);
    expect(afterRes.status).toBe(404);
  });
});
