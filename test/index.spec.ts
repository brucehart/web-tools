import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('Tools index and Markdown viewer', () => {
  it('serves index page at / (unit)', async () => {
    const request = new IncomingRequest('http://example.com/');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Web Tools</title>');
    expect(body).toContain('href="/markdown"');
  });

  it('serves markdown viewer at /markdown (unit)', async () => {
    const request = new IncomingRequest('http://example.com/markdown');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Markdown Viewer</title>');
    expect(body).toContain('textarea id="input"');
  });

  it('serves index page (integration)', async () => {
    const response = await SELF.fetch('https://example.com');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Web Tools</title>');
  });

  it('serves markdown viewer (integration)', async () => {
    const response = await SELF.fetch('https://example.com/markdown');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Markdown Viewer</title>');
  });

  it('serves actuary calculator at /actuary (unit)', async () => {
    const request = new IncomingRequest('http://example.com/actuary');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Actuary Calculator</title>');
    expect(body).toContain('Actuary Calculator');
  });

  it('serves actuary calculator (integration)', async () => {
    const response = await SELF.fetch('https://example.com/actuary');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Actuary Calculator</title>');
  });

  it('rejects missing url for transcript API (unit)', async () => {
    const request = new IncomingRequest('http://example.com/api/yt-transcript', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ url: '' }),
    });
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(400);
    const json = await response.json();
    expect(json.error).toBe('url required');
  });
});

describe('Pretty routes and Pages API', () => {
  it('serves todo list at /todo (unit)', async () => {
    const request = new IncomingRequest('http://example.com/todo');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>To-Do List</title>');
  });

  it('rejects unauthenticated pages list', async () => {
    const request = new IncomingRequest('http://example.com/api/pages/list?tool=markdown');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(401);
  });

  it('creates and fetches a markdown page (unit)', async () => {
    (env as any).INTERNAL_TEST_KEY = 'k';
    const seedReq = new IncomingRequest('http://example.com/api/_internal/seed', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-internal-key': 'k' },
      body: JSON.stringify({ email: 'user@example.com', name: 'User' }),
    });
    const seedCtx = createExecutionContext();
    const seedRes = await worker.fetch(seedReq, env, seedCtx);
    await waitOnExecutionContext(seedCtx);
    expect(seedRes.status).toBe(200);
    const seeded = await seedRes.json<any>();
    const token = String(seeded.token || '');
    expect(token).toContain('t_');

    const createReq = new IncomingRequest('http://example.com/api/pages/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `wt_session=${token}` },
      body: JSON.stringify({ tool: 'markdown', title: 'Test', content: '# Hello' }),
    });
    const createCtx = createExecutionContext();
    const createRes = await worker.fetch(createReq, env, createCtx);
    await waitOnExecutionContext(createCtx);
    expect(createRes.status).toBe(200);
    const created = await createRes.json<any>();
    expect(typeof created.id).toBe('string');

    const listReq = new IncomingRequest('http://example.com/api/pages/list?tool=markdown', {
      headers: { cookie: `wt_session=${token}` },
    });
    const listCtx = createExecutionContext();
    const listRes = await worker.fetch(listReq, env, listCtx);
    await waitOnExecutionContext(listCtx);
    expect(listRes.status).toBe(200);
    const list = await listRes.json<any[]>();
    expect(list.some((r) => r.id === created.id)).toBe(true);

    const getReq = new IncomingRequest(`http://example.com/api/pages/get?id=${encodeURIComponent(created.id)}`, {
      headers: { cookie: `wt_session=${token}` },
    });
    const getCtx = createExecutionContext();
    const getRes = await worker.fetch(getReq, env, getCtx);
    await waitOnExecutionContext(getCtx);
    expect(getRes.status).toBe(200);
    const page = await getRes.json<any>();
    expect(page.id).toBe(created.id);
    expect(page.tool).toBe('markdown');
    expect(page.content).toBe('# Hello');
  });
});
