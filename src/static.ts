import { loadHtml } from './utils/html';
import type { Bindings } from './types';

const PRETTY_ROUTES: Record<string, string> = {
  '/': '/index.html',
  '/markdown': '/markdown.html',
  '/markdown/': '/markdown.html',
  '/euler': '/euler.html',
  '/euler/': '/euler.html',
  '/pastebin': '/pastebin.html',
  '/pastebin/': '/pastebin.html',
  '/date': '/date.html',
  '/date/': '/date.html',
  '/llm-cost': '/llm-cost.html',
  '/llm-cost/': '/llm-cost.html',
  '/yt-transcript': '/yt-transcript.html',
  '/yt-transcript/': '/yt-transcript.html',
  '/tiff-viewer': '/tiff-viewer.html',
  '/tiff-viewer/': '/tiff-viewer.html',
  '/actuary': '/actuary.html',
  '/actuary/': '/actuary.html',
};

const KNOWN_HTML = new Set(Object.values(PRETTY_ROUTES));

export async function serveStatic(request: Request, env: Bindings, url: URL): Promise<Response> {
  const assets = (env as any)?.ASSETS;
  const mappedPath = PRETTY_ROUTES[url.pathname] || url.pathname;
  const assetUrl = new URL(url);
  assetUrl.pathname = mappedPath;
  const assetRequest = new Request(assetUrl.toString(), request);

  if (assets && typeof assets.fetch === 'function') {
    const res = await assets.fetch(assetRequest);
    if (res && res.status !== 404) return res;
  }

  if (KNOWN_HTML.has(mappedPath)) {
    return loadHtml(mappedPath.replace(/^\//, ''));
  }

  return new Response('Not found', { status: 404 });
}
