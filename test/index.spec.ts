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
    expect(body).toContain('href="/diff"');
    expect(body).toContain('href="/base64"');
    expect(body).toContain('href="/image-editor"');
    expect(body).toContain('href="/url-encode-decode"');
    expect(body).toContain('href="/area-code"');
    expect(body).toContain('href="/format-tools"');
    expect(body).toContain('href="/csv-editor"');
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

  it('serves text diff at /diff (unit)', async () => {
    const request = new IncomingRequest('http://example.com/diff');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Text Diff</title>');
    expect(body).toContain('id="originalInput"');
    expect(body).toContain('id="changedInput"');
  });

  it('serves format converter at /format-tools (unit)', async () => {
    const request = new IncomingRequest('http://example.com/format-tools');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Data Format Converter</title>');
    expect(body).toContain('id="sourceFormat"');
    expect(body).toContain('id="targetFormat"');
  });

  it('serves base64 tool at /base64 (unit)', async () => {
    const request = new IncomingRequest('http://example.com/base64');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Base64 Encoder/Decoder</title>');
    expect(body).toContain('id="dropZone"');
    expect(body).toContain('id="decodeInput"');
  });

  it('serves image editor at /image-editor (unit)', async () => {
    const request = new IncomingRequest('http://example.com/image-editor');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Image Editor</title>');
    expect(body).toContain('id="dropZone"');
    expect(body).toContain('id="scaleModePixels"');
    expect(body).toContain('id="scaleModePercent"');
    expect(body).toContain('id="aspectRatioSelect"');
    expect(body).toContain('id="resetScaleButton"');
    expect(body).toContain('id="scalePercentWidth"');
    expect(body).toContain('id="scalePercentHeight"');
    expect(body).toContain('id="scaleWidth"');
    expect(body).toContain('id="exportButton"');
    expect(body).toContain('id="copyImageButton"');
    expect(body).toContain('<option value="avif">AVIF</option>');
  });

  it('serves url encode/decode tool at /url-encode-decode (unit)', async () => {
    const request = new IncomingRequest('http://example.com/url-encode-decode');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>URL Encode/Decode</title>');
    expect(body).toContain('id="inputText"');
    expect(body).toContain('id="outputText"');
    expect(body).toContain('id="moveBtn"');
  });

  it('serves area code lookup at /area-code (unit)', async () => {
    const request = new IncomingRequest('http://example.com/area-code');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
    expect(body).toContain('id="lookupInput"');
    expect(body).toContain('id="resultCard"');
    expect(body).toContain("window.addEventListener('DOMContentLoaded'");
  });

  it('serves area code lookup at /area-code/:code (unit)', async () => {
    const request = new IncomingRequest('http://example.com/area-code/937');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
    expect(body).toContain('id="lookupInput"');
    expect(body).toContain('readPathLookup');
  });

  it('serves csv viewer and editor at /csv-editor (unit)', async () => {
    const request = new IncomingRequest('http://example.com/csv-editor');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>CSV Viewer &amp; Editor</title>');
    expect(body).toContain('id="csvInput"');
    expect(body).toContain('id="sheetHost"');
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

  it('serves text diff (integration)', async () => {
    const response = await SELF.fetch('https://example.com/diff');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Text Diff</title>');
  });

  it('serves format converter (integration)', async () => {
    const response = await SELF.fetch('https://example.com/format-tools');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Data Format Converter</title>');
  });

  it('serves base64 tool (integration)', async () => {
    const response = await SELF.fetch('https://example.com/base64');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Base64 Encoder/Decoder</title>');
  });

  it('serves image editor (integration)', async () => {
    const response = await SELF.fetch('https://example.com/image-editor');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Image Editor</title>');
    expect(body).toContain('id="scaleModePixels"');
    expect(body).toContain('id="aspectRatioSelect"');
    expect(body).toContain('id="copyImageButton"');
    expect(body).toContain('<option value="avif">AVIF</option>');
  });

  it('serves url encode/decode tool (integration)', async () => {
    const response = await SELF.fetch('https://example.com/url-encode-decode');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>URL Encode/Decode</title>');
  });

  it('serves area code lookup (integration)', async () => {
    const response = await SELF.fetch('https://example.com/area-code');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
  });

  it('serves area code lookup at /area-code/:code (integration)', async () => {
    const response = await SELF.fetch('https://example.com/area-code/937');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>Area Code Lookup</title>');
  });

  it('serves csv viewer and editor (integration)', async () => {
    const response = await SELF.fetch('https://example.com/csv-editor');
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');
    const body = await response.text();
    expect(body).toContain('<title>CSV Viewer &amp; Editor</title>');
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
