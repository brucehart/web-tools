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
  '/diff': '/diff.html',
  '/diff/': '/diff.html',
  '/format-tools': '/format-tools.html',
  '/format-tools/': '/format-tools.html',
  '/csv-editor': '/csv-editor.html',
  '/csv-editor/': '/csv-editor.html',
  '/todo': '/todo.html',
  '/todo/': '/todo.html',
  '/date': '/date.html',
  '/date/': '/date.html',
  '/llm-cost': '/llm-cost.html',
  '/llm-cost/': '/llm-cost.html',
  '/goals': '/goals.html',
  '/goals/': '/goals.html',
  '/yt-transcript': '/yt-transcript.html',
  '/yt-transcript/': '/yt-transcript.html',
  '/tiff-viewer': '/tiff-viewer.html',
  '/tiff-viewer/': '/tiff-viewer.html',
  '/base64': '/base64.html',
  '/base64/': '/base64.html',
  '/image-editor': '/image-editor.html',
  '/image-editor/': '/image-editor.html',
  '/url-encode-decode': '/url-encode-decode.html',
  '/url-encode-decode/': '/url-encode-decode.html',
  '/area-code': '/area-code.html',
  '/area-code/': '/area-code.html',
  '/actuary': '/actuary.html',
  '/actuary/': '/actuary.html',
};

const KNOWN_HTML = new Set(Object.values(PRETTY_ROUTES));
const CANONICAL_HTML_ROUTES = new Map<string, string>();

for (const [route, assetPath] of Object.entries(PRETTY_ROUTES)) {
  if (!route.endsWith('/') && !CANONICAL_HTML_ROUTES.has(assetPath)) {
    CANONICAL_HTML_ROUTES.set(assetPath, route);
  }
}

function resolveStaticPath(pathname: string): string {
  if (/^\/area-code\/[^/]+\/?$/.test(pathname)) return '/area-code.html';
  return PRETTY_ROUTES[pathname] || pathname;
}

export async function serveStatic(request: Request, env: Bindings, url: URL): Promise<Response> {
  const mappedPath = resolveStaticPath(url.pathname);
  const assets = (env as any)?.ASSETS;

  if (KNOWN_HTML.has(mappedPath)) {
    const canonicalRoute = CANONICAL_HTML_ROUTES.get(mappedPath) || mappedPath;
    if (assets && typeof assets.fetch === 'function') {
      const assetUrl = new URL(url);
      assetUrl.pathname = canonicalRoute;
      const assetRequest = new Request(assetUrl.toString(), request);
      const res = await assets.fetch(assetRequest);
      if (res && res.status !== 404) return res;
    }
    return loadHtml(mappedPath.replace(/^\//, ''));
  }

  if (assets && typeof assets.fetch === 'function') {
    const assetUrl = new URL(url);
    assetUrl.pathname = mappedPath;
    const assetRequest = new Request(assetUrl.toString(), request);
    const res = await assets.fetch(assetRequest);
    if (res && res.status !== 404) return res;
  }

  return new Response('Not found', { status: 404 });
}
