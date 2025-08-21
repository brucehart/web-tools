/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
// HTML templates moved to /public and served via ASSETS binding.

async function loadHtml(filename: string): Promise<Response> {
  const url = new URL(`../public/${filename}`, import.meta.url);
  const res = await fetch(url);
  if (!res.ok) return new Response('Not found', { status: 404 });
  const body = await res.text();
  return new Response(body, {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    },
  });
}

// See public/markdown.html for the Markdown viewer page.

export default {
  async fetch(request, env, _ctx): Promise<Response> {
    const url = new URL(request.url);
    let path = url.pathname;
    if (path === '/' || path === '') path = '/index.html';
    else if (path === '/markdown' || path === '/markdown/') path = '/markdown.html';

    const assetUrl = new URL(url);
    assetUrl.pathname = path;
    const assetRequest = new Request(assetUrl.toString(), request);

    const assets = (env as any)?.ASSETS;
    if (assets && typeof assets.fetch === 'function') {
      const res = await assets.fetch(assetRequest);
      if (res && res.status !== 404) return res;
    }

    // Fallback to bundled HTML (tests/dev) if assets binding unavailable
    if (path.endsWith('markdown.html')) return loadHtml('markdown.html');
    if (path.endsWith('index.html')) return loadHtml('index.html');

    return new Response('Not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
