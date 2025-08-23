/**
 * Worker entry with static assets and a new /pastebin tool backed by D1.
 * Google OAuth is used for accounts; pastes can be public or unlisted.
 */

// HTML templates moved to /public and served via ASSETS binding.

type Bindings = Env & {
  DB: D1Database;
  ASSETS: Fetcher;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string; // set as secret via wrangler
  OAUTH_REDIRECT_URL?: string;
  SESSION_COOKIE_NAME?: string;
};

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

function json(data: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(data), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
    ...init,
  });
}

function badRequest(message: string, status = 400): Response {
  return new Response(message, { status });
}

function getCookies(req: Request): Record<string, string> {
  const h = req.headers.get('cookie') || '';
  const out: Record<string, string> = {};
  h.split(/;\s*/).forEach((p) => {
    if (!p) return;
    const idx = p.indexOf('=');
    if (idx === -1) return;
    const k = decodeURIComponent(p.slice(0, idx).trim());
    const v = decodeURIComponent(p.slice(idx + 1).trim());
    out[k] = v;
  });
  return out;
}

function setCookie(res: Response, name: string, value: string, attrs: Record<string, string | number | boolean> = {}) {
  const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];
  if (attrs.path !== undefined) parts.push(`Path=${attrs.path}`);
  if (attrs.httpOnly !== false) parts.push('HttpOnly');
  if (attrs.sameSite !== undefined) parts.push(`SameSite=${attrs.sameSite}`);
  if (attrs.secure !== false) parts.push('Secure');
  if (attrs.maxAge !== undefined) parts.push(`Max-Age=${attrs.maxAge}`);
  if (attrs.expires !== undefined) parts.push(`Expires=${attrs.expires}`);
  // Important: append separate Set-Cookie headers; do not join with newlines
  res.headers.append('Set-Cookie', parts.join('; '));
}

async function readJson<T = any>(req: Request): Promise<T> {
  const ct = req.headers.get('content-type') || '';
  if (ct.includes('application/json')) return await req.json<T>();
  const text = await req.text();
  try { return JSON.parse(text) as T; } catch { return {} as T; }
}

function urlSafeRandom(len = 12): string {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  const alph = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  for (let i = 0; i < len; i++) out += alph[bytes[i] % alph.length];
  return out;
}

async function getSessionUser(req: Request, env: Bindings): Promise<{ id: string; email?: string; name?: string; picture?: string } | null> {
  const cookieName = env.SESSION_COOKIE_NAME || 'wt_session';
  const cookies = getCookies(req);
  const token = cookies[cookieName];
  if (!token) return null;
  const row = await env.DB.prepare('SELECT u.id, u.email, u.name, u.picture FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?').bind(token).first();
  if (!row) return null;
  return row as any;
}

async function requireUser(req: Request, env: Bindings): Promise<{ id: string; email?: string } | Response> {
  const user = await getSessionUser(req, env);
  if (!user) return new Response('Unauthorized', { status: 401 });
  return user;
}

function isAllowedEmail(email?: string | null): boolean {
  return (email || '').toLowerCase() === 'bruce.hart@gmail.com';
}

async function requireAllowedUser(req: Request, env: Bindings): Promise<{ id: string; email?: string } | Response> {
  const u = await getSessionUser(req, env);
  if (!u) return new Response('Unauthorized', { status: 401 });
  if (!isAllowedEmail(u.email || '')) return new Response('Forbidden', { status: 403 });
  return u;
}

export default {
  async fetch(request, env, _ctx): Promise<Response> {
    const b = env as unknown as Bindings;
    const url = new URL(request.url);
    let path = url.pathname;

    // -------- Auth API --------
    if (path === '/api/auth/me' && request.method === 'GET') {
      const user = await getSessionUser(request, b);
      return json({ loggedIn: !!user, user, allowed: !!(user && isAllowedEmail(user.email || '')) });
    }
    if (path === '/api/auth/logout' && request.method === 'POST') {
      const cookieName = b.SESSION_COOKIE_NAME || 'wt_session';
      const token = getCookies(request)[cookieName];
      if (token) await b.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
      const res = json({ ok: true });
      setCookie(res, cookieName, '', { path: '/', maxAge: 0, httpOnly: true, secure: true, sameSite: 'Lax' });
      return res;
    }
    if (path === '/auth/google/login' && request.method === 'GET') {
      const clientId = b.GOOGLE_CLIENT_ID;
      const redirect = b.OAUTH_REDIRECT_URL;
      if (!clientId || !redirect) return badRequest('Google OAuth not configured', 500);
      const state = urlSafeRandom(16);
      const oauthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      oauthUrl.searchParams.set('client_id', clientId);
      oauthUrl.searchParams.set('redirect_uri', redirect);
      oauthUrl.searchParams.set('response_type', 'code');
      oauthUrl.searchParams.set('scope', 'openid email profile');
      oauthUrl.searchParams.set('state', state);
      const res = new Response(null, { status: 302, headers: { location: oauthUrl.toString() } });
      setCookie(res, 'oauth_state', state, { path: '/', httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 600 });
      return res;
    }
    if (path === '/auth/google/callback' && request.method === 'GET') {
      const state = url.searchParams.get('state') || '';
      const code = url.searchParams.get('code') || '';
      const cookieState = getCookies(request)['oauth_state'];
      if (!code || !state || !cookieState || state !== cookieState) return badRequest('Invalid state');
      const clientId = b.GOOGLE_CLIENT_ID || '';
      const clientSecret = (b as any).GOOGLE_CLIENT_SECRET as string | undefined;
      const redirect = b.OAUTH_REDIRECT_URL || '';
      if (!clientId || !clientSecret || !redirect) return badRequest('OAuth not configured', 500);
      const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirect,
          grant_type: 'authorization_code',
        }),
      });
      if (!tokenRes.ok) return badRequest('Token exchange failed', 500);
      const tokenJson = await tokenRes.json<any>();
      const accessToken = tokenJson.access_token as string;
      if (!accessToken) return badRequest('No access token', 500);
      const infoRes = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      if (!infoRes.ok) return badRequest('Failed to fetch userinfo', 500);
      const info = await infoRes.json<any>();
      const sub = String(info.sub);
      const email = String(info.email || '');
      const name = String(info.name || '');
      const picture = String(info.picture || '');
      await b.DB.prepare('INSERT INTO users (id, email, name, picture) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET email=excluded.email, name=excluded.name, picture=excluded.picture')
        .bind(sub, email, name, picture)
        .run();
      const token = urlSafeRandom(24);
      const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toUTCString();
      await b.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, sub, expiresAt).run();
      const res = new Response(null, { status: 302, headers: { location: '/pastebin' } });
      setCookie(res, 'oauth_state', '', { path: '/', maxAge: 0 });
      setCookie(res, b.SESSION_COOKIE_NAME || 'wt_session', token, { path: '/', httpOnly: true, secure: true, sameSite: 'Lax', maxAge: 60 * 60 * 24 * 7 });
      return res;
    }

    // -------- Pastebin API --------
    if (path === '/api/pastebin/create' && request.method === 'POST') {
      const user = await requireAllowedUser(request, b);
      if (user instanceof Response) return user;
      const body = await readJson<{ title?: string; content?: string; visibility?: 'public' | 'unlisted' | 'private' }>(request);
      const content = (body.content || '').toString();
      const title = (body.title || '').toString().slice(0, 200);
      const visibility = (body.visibility === 'unlisted'
        ? 'unlisted'
        : body.visibility === 'private'
        ? 'private'
        : 'public') as 'public' | 'unlisted' | 'private';
      if (!content) return badRequest('content required');
      for (let i = 0; i < 5; i++) {
        const slug = visibility === 'public' ? urlSafeRandom(8) : urlSafeRandom(14);
        const exists = await b.DB.prepare('SELECT id FROM pastes WHERE id = ?').bind(slug).first();
        if (exists) continue;
        await b.DB.prepare('INSERT INTO pastes (id, user_id, title, content, visibility) VALUES (?, ?, ?, ?, ?)')
          .bind(slug, (user as any).id, title, content, visibility)
          .run();
        return json({ id: slug });
      }
      return badRequest('Failed to allocate id', 500);
    }
    if (path === '/api/pastebin/mine' && request.method === 'GET') {
      const user = await requireAllowedUser(request, b);
      if (user instanceof Response) return user;
      const rows = await b.DB.prepare('SELECT id, title, visibility, created_at FROM pastes WHERE user_id = ? ORDER BY created_at DESC LIMIT 200').bind((user as any).id).all();
      return json(rows.results || []);
    }
    if (path === '/api/pastebin/public' && request.method === 'GET') {
      const rows = await b.DB.prepare("SELECT id, title, visibility, created_at FROM pastes WHERE visibility = 'public' ORDER BY created_at DESC LIMIT 200").all();
      return json(rows.results || []);
    }
    if (path === '/api/pastebin/get' && request.method === 'GET') {
      const id = url.searchParams.get('id') || '';
      if (!id) return badRequest('id required');
      const row = (await b.DB.prepare('SELECT id, user_id, title, content, visibility, created_at FROM pastes WHERE id = ?').bind(id).first()) as any;
      if (!row) return new Response('Not found', { status: 404 });
      const me = await getSessionUser(request, b);
      if (row.visibility === 'private') {
        if (!me || me.id !== row.user_id) return new Response('Forbidden', { status: 403 });
      }
      const can_delete = !!(me && me.id === row.user_id);
      const { user_id, ...rest } = row;
      return json({ ...rest, can_delete });
    }
    if (path === '/api/pastebin/delete' && request.method === 'POST') {
      const user = await requireAllowedUser(request, b);
      if (user instanceof Response) return user;
      const body = await readJson<{ id?: string }>(request);
      const id = (body.id || '').toString();
      if (!id) return badRequest('id required');
      const row = (await b.DB.prepare('SELECT user_id FROM pastes WHERE id = ?').bind(id).first()) as any;
      if (!row) return new Response('Not found', { status: 404 });
      if (row.user_id !== (user as any).id) return new Response('Forbidden', { status: 403 });
      await b.DB.prepare('DELETE FROM pastes WHERE id = ?').bind(id).run();
      return json({ ok: true });
    }

    // -------- Static/HTML routing --------
    if (path === '/' || path === '') path = '/index.html';
    else if (path === '/markdown' || path === '/markdown/') path = '/markdown.html';
    else if (path === '/euler' || path === '/euler/') path = '/euler.html';
    else if (path === '/pastebin' || path === '/pastebin/') path = '/pastebin.html';
    else if (path.startsWith('/pastebin/p/')) {
      // Serve pastebin page with the ID injected for robust client rendering
      const id = path.replace(/^\/pastebin\/p\//, '').replace(/\/$/, '');
      // Try assets binding first
      const assetUrl = new URL(url);
      assetUrl.pathname = '/pastebin.html';
      const assetRequest = new Request(assetUrl.toString(), request);
      const assets = (env as any)?.ASSETS;
      let html: string | null = null;
      if (assets && typeof assets.fetch === 'function') {
        const res = await assets.fetch(assetRequest);
        if (res && res.status !== 404) {
          html = await res.text();
        }
      }
      if (!html) {
        // If the asset binding isn't available, redirect to absolute /pastebin?id=... so client can fetch.
        const redirectUrl = new URL(request.url);
        redirectUrl.pathname = '/pastebin';
        redirectUrl.search = `?id=${encodeURIComponent(id)}`;
        return Response.redirect(redirectUrl.toString(), 302);
      }
      const injected = html.replace('</body>', `<script>window.PASTE_ID=${JSON.stringify(id)};<\/script></body>`);
      return new Response(injected, { headers: { 'content-type': 'text/html; charset=utf-8' } });
    }

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
    if (path.endsWith('euler.html')) return loadHtml('euler.html');
    if (path.endsWith('pastebin.html')) return loadHtml('pastebin.html');
    if (path.endsWith('index.html')) return loadHtml('index.html');

    return new Response('Not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
