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

const YT_WATCH_URL = 'https://www.youtube.com/watch';
const YT_PLAYER_URL = 'https://www.youtube.com/youtubei/v1/player';
const YT_USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36,gzip(gfe)';

class TranscriptFetchError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

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

function extractVideoId(input: string): string | null {
  const trimmed = input.trim();
  const idMatch = /^[a-zA-Z0-9_-]{11}$/;
  if (idMatch.test(trimmed)) return trimmed;
  try {
    const url = new URL(trimmed);
    if (url.hostname === 'youtu.be') {
      const part = url.pathname.replace(/^\//, '').split('/')[0];
      if (idMatch.test(part)) return part;
    }
    if (url.hostname.includes('youtube.com')) {
      const v = url.searchParams.get('v');
      if (v && idMatch.test(v)) return v;
      const segments = url.pathname.split('/').filter(Boolean);
      for (const seg of segments) {
        if (idMatch.test(seg)) return seg;
      }
    }
  } catch {
    // fall through to regex extraction
  }
  const manual = trimmed.match(/(?:v=|\/)([a-zA-Z0-9_-]{11})(?:[&?/]|$)/);
  if (manual && manual[1]) return manual[1];
  return null;
}

function decodeHtmlEntities(text: string): string {
  if (!text) return '';
  const map: Record<string, string> = {
    amp: '&',
    lt: '<',
    gt: '>',
    quot: '"',
    apos: "'",
    nbsp: ' ',
  };
  return text
    .replace(/&#(x?[0-9a-fA-F]+);/g, (_, entity: string) => {
      if (!entity) return '';
      if (entity.startsWith('x') || entity.startsWith('X')) {
        const code = Number.parseInt(entity.slice(1), 16);
        return Number.isFinite(code) ? String.fromCharCode(code) : '';
      }
      const code = Number.parseInt(entity, 10);
      return Number.isFinite(code) ? String.fromCharCode(code) : '';
    })
    .replace(/&([a-zA-Z]+);/g, (_, entity: string) => map[entity] ?? '');
}

function parseTranscriptXml(xml: string): { text: string; offset: number; duration: number }[] {
  const results: { text: string; offset: number; duration: number }[] = [];
  const regex = /<text start="([^"]*)"(?: dur="([^"]*)")?>(.*?)<\/text>/gs;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(xml)) !== null) {
    const [, startRaw, durationRaw, payload] = match;
    let text = payload || '';
    text = text.replace(/<[^>]+>/g, ' ');
    text = decodeHtmlEntities(text);
    text = text.replace(/\s+/g, ' ').trim();
    if (!text) continue;
    const offset = Number.parseFloat(startRaw || '0');
    const duration = Number.parseFloat(durationRaw || '0');
    results.push({ text, offset: Number.isFinite(offset) ? offset : 0, duration: Number.isFinite(duration) ? duration : 0 });
  }
  return results;
}

function parseWatchConfig(html: string): { apiKey?: string; context?: any; clientVersion?: string } {
  const cfg: Record<string, unknown> = {};
  const matches = html.matchAll(/ytcfg\.set\(({.*?})\);/gs);
  for (const match of matches) {
    const blob = match[1];
    try {
      const parsed = JSON.parse(blob);
      Object.assign(cfg, parsed);
    } catch {
      // ignore malformed blobs
    }
  }
  let apiKey = typeof cfg['INNERTUBE_API_KEY'] === 'string' ? String(cfg['INNERTUBE_API_KEY']) : undefined;
  if (!apiKey) {
    const keyFallback = html.match(/"INNERTUBE_API_KEY":"([^"]+)"/);
    if (keyFallback) apiKey = keyFallback[1];
  }
  const context = (typeof cfg['INNERTUBE_CONTEXT'] === 'object' && cfg['INNERTUBE_CONTEXT']) ? JSON.parse(JSON.stringify(cfg['INNERTUBE_CONTEXT'])) : undefined;
  let clientVersion = typeof cfg['INNERTUBE_CLIENT_VERSION'] === 'string' ? String(cfg['INNERTUBE_CLIENT_VERSION']) : undefined;
  if (!clientVersion && context && typeof (context as any).client?.clientVersion === 'string') {
    clientVersion = String((context as any).client.clientVersion);
  }
  return { apiKey, context, clientVersion };
}

async function fetchYouTubeTranscript(source: string, language?: string): Promise<{ text: string; offset: number; duration: number }[]> {
  const videoId = extractVideoId(source);
  if (!videoId) throw new TranscriptFetchError(400, 'Unable to determine YouTube video ID.');
  const lang = (language || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '') || undefined;

  const watchUrl = new URL(YT_WATCH_URL);
  watchUrl.searchParams.set('v', videoId);
  if (lang) watchUrl.searchParams.set('hl', lang);

  const acceptLang = lang ? `${lang},${lang.split('-')[0]};q=0.9,en;q=0.8` : 'en-US,en;q=0.9';
  const watchRes = await fetch(watchUrl.toString(), {
    headers: {
      'user-agent': YT_USER_AGENT,
      'accept-language': acceptLang,
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
  });
  if (watchRes.status === 404) throw new TranscriptFetchError(404, 'Video not found.');
  if (!watchRes.ok) throw new TranscriptFetchError(502, 'Failed to fetch video details from YouTube.');
  const html = await watchRes.text();
  const { apiKey, context, clientVersion } = parseWatchConfig(html);
  if (!apiKey) throw new TranscriptFetchError(500, 'Unable to read YouTube API key.');

  const ctx = context ? JSON.parse(JSON.stringify(context)) : { client: { clientName: 'WEB', clientVersion: clientVersion || '2.20250126.01.00', hl: 'en', gl: 'US' } };
  if (!ctx.client || typeof ctx.client !== 'object') ctx.client = { clientName: 'WEB', clientVersion: clientVersion || '2.20250126.01.00', hl: 'en', gl: 'US' };
  if (!ctx.client.clientName) ctx.client.clientName = 'WEB';
  if (!ctx.client.clientVersion) ctx.client.clientVersion = clientVersion || '2.20250126.01.00';
  if (lang) ctx.client.hl = lang;
  else if (!ctx.client.hl) ctx.client.hl = 'en';
  if (!ctx.client.gl) ctx.client.gl = 'US';

  const playerRes = await fetch(`${YT_PLAYER_URL}?key=${encodeURIComponent(apiKey)}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': YT_USER_AGENT,
      'accept-language': acceptLang,
    },
    body: JSON.stringify({
      context: ctx,
      videoId,
    }),
  });
  if (!playerRes.ok) {
    if (playerRes.status === 404) throw new TranscriptFetchError(404, 'Video not found.');
    throw new TranscriptFetchError(502, 'Failed to load transcript metadata from YouTube.');
  }
  const playerData = await playerRes.json<any>();
  const playability = playerData?.playabilityStatus?.status;
  if (playability && playability !== 'OK') {
    if (playability === 'LOGIN_REQUIRED') throw new TranscriptFetchError(403, 'This video requires sign-in to view transcripts.');
    throw new TranscriptFetchError(403, playerData?.playabilityStatus?.reason || 'Transcripts unavailable for this video.');
  }

  const captionRenderer = playerData?.captions?.playerCaptionsTracklistRenderer;
  const captionTracks = captionRenderer?.captionTracks as Array<any> | undefined;
  if (!captionTracks || captionTracks.length === 0) throw new TranscriptFetchError(404, 'No transcripts are available for this video.');

  const normalizedLang = lang;
  const primaryMatch = normalizedLang ? captionTracks.find((track) => typeof track.languageCode === 'string' && track.languageCode.toLowerCase() === normalizedLang) : undefined;
  const fallbackMatch = normalizedLang && !primaryMatch
    ? captionTracks.find((track) => {
        if (typeof track.languageCode !== 'string') return false;
        const primary = track.languageCode.toLowerCase().split('-')[0];
        return primary && primary === normalizedLang.split('-')[0];
      })
    : undefined;

  let chosenTrack = primaryMatch || fallbackMatch || captionTracks[0];
  if (!chosenTrack?.baseUrl) throw new TranscriptFetchError(404, 'Failed to resolve a valid transcript track.');

  const availableLangs = captionTracks
    .map((track) => (typeof track.languageCode === 'string' ? track.languageCode : ''))
    .filter(Boolean);

  let transcriptUrl = String(chosenTrack.baseUrl);
  let usedTranslation = false;
  if (normalizedLang && !primaryMatch && !fallbackMatch) {
    const translations = Array.isArray(captionRenderer?.translationLanguages) ? captionRenderer.translationLanguages : [];
    const desired = translations.find((entry: any) => {
      const code = String(entry?.languageCode || '').toLowerCase();
      if (!code) return false;
      if (code === normalizedLang) return true;
      return code.split('-')[0] === normalizedLang.split('-')[0];
    });
    if (!desired) {
      throw new TranscriptFetchError(404, `Transcripts are not available in ${language}. Available languages: ${availableLangs.join(', ')}`);
    }
    const translatableTrack = captionTracks.find((track) => track?.isTranslatable) || chosenTrack;
    transcriptUrl = String(translatableTrack.baseUrl);
    transcriptUrl = transcriptUrl.replace(/&fmt=[^&]*/g, '');
    transcriptUrl += `&tlang=${encodeURIComponent(String(desired.languageCode))}`;
    usedTranslation = true;
  }

  if (!usedTranslation) {
    transcriptUrl = transcriptUrl.replace(/&fmt=[^&]*/g, '');
  }

  const transcriptRes = await fetch(transcriptUrl, {
    headers: {
      'user-agent': YT_USER_AGENT,
      'accept-language': acceptLang,
    },
  });
  if (!transcriptRes.ok) throw new TranscriptFetchError(502, 'Failed to download transcript data from YouTube.');
  const xml = await transcriptRes.text();
  const segments = parseTranscriptXml(xml);
  if (segments.length === 0) throw new TranscriptFetchError(404, 'Transcript data was empty for this video.');
  return segments;
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
      const user = await requireUser(request, b);
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
      const user = await requireUser(request, b);
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
      const user = await requireUser(request, b);
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

    if (path === '/api/yt-transcript' && request.method === 'POST') {
      const body = await readJson<{ url?: string; lang?: string }>(request);
      const input = (body.url || '').toString().trim();
      const lang = (body.lang || '').toString().trim();
      if (!input) return json({ error: 'url required' }, { status: 400 });
      try {
        const transcript = await fetchYouTubeTranscript(input, lang || undefined);
        return json({ transcript });
      } catch (err) {
        if (err instanceof TranscriptFetchError) {
          return json({ error: err.message }, { status: err.status });
        }
        console.error('yt-transcript error', err);
        return json({ error: 'Failed to fetch transcript' }, { status: 502 });
      }
    }

    // -------- Static/HTML routing --------
    if (path === '/' || path === '') path = '/index.html';
    else if (path === '/markdown' || path === '/markdown/') path = '/markdown.html';
    else if (path === '/euler' || path === '/euler/') path = '/euler.html';
    else if (path === '/pastebin' || path === '/pastebin/') path = '/pastebin.html';
    else if (path === '/date' || path === '/date/') path = '/date.html';
    else if (path === '/llm-cost' || path === '/llm-cost/') path = '/llm-cost.html';
    else if (path === '/yt-transcript' || path === '/yt-transcript/') path = '/yt-transcript.html';
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
    if (path.endsWith('date.html')) return loadHtml('date.html');
    if (path.endsWith('llm-cost.html')) return loadHtml('llm-cost.html');
    if (path.endsWith('yt-transcript.html')) return loadHtml('yt-transcript.html');
    if (path.endsWith('index.html')) return loadHtml('index.html');

    return new Response('Not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
