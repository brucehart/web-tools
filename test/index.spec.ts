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
    expect(body).toContain('<title>Markdown Preview</title>');
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
    expect(body).toContain('<title>Markdown Preview</title>');
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
