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
    expect(body).toContain('<title>Markdown to HTML Viewer</title>');
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
    expect(body).toContain('<title>Markdown to HTML Viewer</title>');
  });
});
