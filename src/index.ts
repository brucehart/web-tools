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
const INNERTUBE_CONTEXT = Object.freeze({
  client: {
    clientName: 'ANDROID',
    clientVersion: '20.10.38',
  },
});

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

async function loadStaticAsset(filename: string, contentType: string): Promise<Response> {
  const url = new URL(`../public/${filename}`, import.meta.url);
  const res = await fetch(url);
  if (!res.ok) return new Response('Not found', { status: 404 });
  const body = await res.arrayBuffer();
  return new Response(body, {
    headers: {
      'content-type': contentType,
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

type CookieJar = Map<string, string>;

function getSetCookieHeaders(headers: Headers): string[] {
  const anyHeaders = headers as Headers & { getSetCookie?: () => string[]; raw?: () => Record<string, string[]> };
  if (typeof anyHeaders.getSetCookie === 'function') {
    try {
      const values = anyHeaders.getSetCookie();
      if (Array.isArray(values) && values.length > 0) return values;
    } catch {
      // ignore runtime-specific method failures
    }
  }
  if (typeof anyHeaders.raw === 'function') {
    try {
      const raw = anyHeaders.raw();
      const values = raw['set-cookie'];
      if (Array.isArray(values) && values.length > 0) return values;
    } catch {
      // ignore runtime-specific method failures
    }
  }
  const combined = headers.get('set-cookie');
  if (!combined) return [];
  const result: string[] = [];
  let start = 0;
  let inQuotes = false;
  let inExpires = false;
  for (let i = 0; i < combined.length; i++) {
    const ch = combined[i];
    if (!inQuotes) {
      if (!inExpires && combined.slice(i, i + 8).toLowerCase() === 'expires=') {
        inExpires = true;
      } else if (inExpires && ch === ';') {
        inExpires = false;
      }
    }
    if (ch === '"') inQuotes = !inQuotes;
    if (ch === ',' && !inQuotes && !inExpires) {
      const piece = combined.slice(start, i).trim();
      if (piece) result.push(piece);
      start = i + 1;
    }
  }
  const last = combined.slice(start).trim();
  if (last) result.push(last);
  return result;
}

function setCookieFromHeader(cookie: string, jar: CookieJar): void {
  const eqIndex = cookie.indexOf('=');
  if (eqIndex <= 0) return;
  const name = cookie.slice(0, eqIndex).trim();
  if (!name) return;
  const end = cookie.indexOf(';', eqIndex + 1);
  const value = cookie.slice(eqIndex + 1, end === -1 ? undefined : end).trim();
  jar.set(name, value);
}

function trackResponseCookies(res: Response, jar: CookieJar): void {
  const cookies = getSetCookieHeaders(res.headers);
  for (const cookie of cookies) setCookieFromHeader(cookie, jar);
}

function buildCookieHeader(jar: CookieJar): string | undefined {
  if (jar.size === 0) return undefined;
  return Array.from(jar.entries())
    .map(([key, value]) => `${key}=${value}`)
    .join('; ');
}

async function fetchWithCookies(url: string, jar: CookieJar, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers || {});
  const cookieHeader = buildCookieHeader(jar);
  if (cookieHeader) headers.set('cookie', cookieHeader);
  if (!headers.has('user-agent')) headers.set('user-agent', YT_USER_AGENT);
  const response = await fetch(url, { ...init, headers });
  trackResponseCookies(response, jar);
  return response;
}

async function fetchWatchHtml(videoId: string, acceptLang: string, jar: CookieJar): Promise<string> {
  const watchUrl = new URL(YT_WATCH_URL);
  watchUrl.searchParams.set('v', videoId);
  const headers = new Headers({
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': acceptLang,
    'user-agent': YT_USER_AGENT,
  });
  let response = await fetchWithCookies(watchUrl.toString(), jar, { headers });
  if (response.status === 404) throw new TranscriptFetchError(404, 'Video not found.');
  if (!response.ok) throw new TranscriptFetchError(502, 'Failed to fetch video details from YouTube.');
  let html = await response.text();
  if (html.includes('action="https://consent.youtube.com/s"')) {
    const consentMatch = html.match(/name="v" value="(.*?)"/);
    if (!consentMatch) throw new TranscriptFetchError(502, 'Failed to satisfy YouTube consent flow.');
    const consentValue = decodeHtmlEntities(consentMatch[1] || '');
    if (!consentValue) throw new TranscriptFetchError(502, 'Failed to satisfy YouTube consent flow.');
    jar.set('CONSENT', `YES+${consentValue}`);
    response = await fetchWithCookies(watchUrl.toString(), jar, { headers });
    if (!response.ok) throw new TranscriptFetchError(502, 'Failed to accept YouTube consent page.');
    html = await response.text();
  }
  if (html.includes('class="g-recaptcha"')) {
    throw new TranscriptFetchError(429, 'YouTube is blocking transcript requests from this IP (captcha required).');
  }
  return html;
}

function extractInnertubeApiKey(html: string): string {
  const match = html.match(/"INNERTUBE_API_KEY":"([^"]+)"/);
  if (match && match[1]) return match[1];
  throw new TranscriptFetchError(500, 'Unable to read YouTube API key.');
}

function cloneInnertubeContext(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(INNERTUBE_CONTEXT));
}

interface TranscriptTrack {
  url: string;
  languageCode: string;
  languageName: string;
  isGenerated: boolean;
  isTranslatable: boolean;
}

interface TranslationLanguage {
  languageCode: string;
  languageName: string;
}

interface TranscriptCatalog {
  manual: Map<string, TranscriptTrack>;
  generated: Map<string, TranscriptTrack>;
  translationLanguages: TranslationLanguage[];
}

function buildTranscriptCatalog(renderer: any): TranscriptCatalog {
  const manual = new Map<string, TranscriptTrack>();
  const generated = new Map<string, TranscriptTrack>();
  const translationLanguages: TranslationLanguage[] = Array.isArray(renderer?.translationLanguages)
    ? renderer.translationLanguages
        .map((lang: any) => {
          const languageCode = String(lang?.languageCode || '').toLowerCase();
          if (!languageCode) return null;
          const languageName = String(
            lang?.languageName?.simpleText ||
              lang?.languageName?.runs?.[0]?.text ||
              languageCode,
          );
          return { languageCode, languageName };
        })
        .filter((entry: TranslationLanguage | null): entry is TranslationLanguage => !!entry)
    : [];

  const tracks = Array.isArray(renderer?.captionTracks) ? renderer.captionTracks : [];
  for (const track of tracks) {
    if (!track?.baseUrl || !track?.languageCode) continue;
    const languageCode = String(track.languageCode).toLowerCase();
    const languageName = String(
      track?.name?.simpleText ||
        track?.name?.runs?.[0]?.text ||
        track?.languageCode,
    );
    const descriptor: TranscriptTrack = {
      url: String(track.baseUrl).replace(/&fmt=[^&]*/g, ''),
      languageCode,
      languageName,
      isGenerated: String(track?.kind || '') === 'asr',
      isTranslatable: !!track?.isTranslatable,
    };
    if (descriptor.isGenerated) generated.set(languageCode, descriptor);
    else manual.set(languageCode, descriptor);
  }

  return { manual, generated, translationLanguages };
}

function getAvailableLanguages(catalog: TranscriptCatalog): string[] {
  return Array.from(new Set<string>([
    ...catalog.manual.keys(),
    ...catalog.generated.keys(),
  ]));
}

function findTranscriptByPreference(catalog: TranscriptCatalog, preferences: string[]): TranscriptTrack | undefined {
  for (const pref of preferences) {
    const code = pref.trim().toLowerCase();
    if (!code) continue;
    const manual = catalog.manual.get(code);
    if (manual) return manual;
    const generated = catalog.generated.get(code);
    if (generated) return generated;
  }
  return undefined;
}

function selectTranslationTarget(catalog: TranscriptCatalog, desired: string): { track: TranscriptTrack; targetLanguageCode: string } | null {
  const normalizedDesired = desired.toLowerCase();
  const languagePrimary = normalizedDesired.split('-')[0] || normalizedDesired;
  const translation = catalog.translationLanguages.find((entry) => entry.languageCode === normalizedDesired)
    || catalog.translationLanguages.find((entry) => entry.languageCode.split('-')[0] === languagePrimary);
  if (!translation) return null;
  const translatableSource = [...catalog.manual.values(), ...catalog.generated.values()].find((track) => track.isTranslatable);
  if (!translatableSource) return null;
  return { track: translatableSource, targetLanguageCode: translation.languageCode };
}

function assertPlayability(status: any, videoId: string): void {
  const playabilityStatus = status?.status;
  if (!playabilityStatus || playabilityStatus === 'OK') return;
  const reason = String(status?.reason || '').trim();
  const subreasonRuns = status?.errorScreen?.playerErrorMessageRenderer?.subreason?.runs;
  const subreason = Array.isArray(subreasonRuns)
    ? subreasonRuns.map((run: any) => String(run?.text || '')).filter(Boolean).join(' ')
    : '';
  if (playabilityStatus === 'LOGIN_REQUIRED') {
    if (/not a bot/i.test(reason)) {
      throw new TranscriptFetchError(429, 'YouTube is blocking transcript requests from this IP (captcha required).');
    }
    if (/inappropriate/.test(reason)) {
      throw new TranscriptFetchError(403, 'This video is age-restricted and requires sign-in.');
    }
    throw new TranscriptFetchError(403, reason || 'This video requires sign-in to view transcripts.');
  }
  if (playabilityStatus === 'ERROR' && reason === 'This video is unavailable') {
    throw new TranscriptFetchError(404, 'Video not available.');
  }
  if (playabilityStatus === 'UNPLAYABLE' && reason) {
    throw new TranscriptFetchError(403, reason);
  }
  if (playabilityStatus === 'AGE_CHECK_REQUIRED') {
    throw new TranscriptFetchError(403, 'This video is age-restricted and requires sign-in.');
  }
  const message = reason || subreason || 'Transcripts unavailable for this video.';
  throw new TranscriptFetchError(403, message);
}

async function fetchYouTubeTranscript(source: string, language?: string): Promise<{ text: string; offset: number; duration: number }[]> {
  const videoId = extractVideoId(source);
  if (!videoId) throw new TranscriptFetchError(400, 'Unable to determine YouTube video ID.');
  const normalizedLang = (language || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '') || undefined;
  const requestedLanguageLabel = (language || '').trim() || normalizedLang || 'the requested language';
  const cookieJar: CookieJar = new Map<string, string>();
  const langPrimary = normalizedLang ? normalizedLang.split('-')[0] || normalizedLang : undefined;
  const acceptLang = normalizedLang && langPrimary
    ? `${normalizedLang},${langPrimary};q=0.9,en;q=0.8`
    : 'en-US,en;q=0.9';

  const html = await fetchWatchHtml(videoId, acceptLang, cookieJar);
  const apiKey = extractInnertubeApiKey(html);

  const playerRes = await fetchWithCookies(`${YT_PLAYER_URL}?key=${encodeURIComponent(apiKey)}`, cookieJar, {
    method: 'POST',
    headers: {
      'accept-language': acceptLang,
      'content-type': 'application/json',
      'user-agent': YT_USER_AGENT,
    },
    body: JSON.stringify({
      context: cloneInnertubeContext(),
      videoId,
    }),
  });
  if (playerRes.status === 404) throw new TranscriptFetchError(404, 'Video not found.');
  if (!playerRes.ok) throw new TranscriptFetchError(502, 'Failed to load transcript metadata from YouTube.');
  const playerData = await playerRes.json<any>();
  assertPlayability(playerData?.playabilityStatus, videoId);

  const captionRenderer = playerData?.captions?.playerCaptionsTracklistRenderer;
  if (!captionRenderer) throw new TranscriptFetchError(404, 'No transcripts are available for this video.');

  const catalog = buildTranscriptCatalog(captionRenderer);
  if (catalog.manual.size === 0 && catalog.generated.size === 0) {
    throw new TranscriptFetchError(404, 'No transcripts are available for this video.');
  }

  const preferenceList: string[] = [];
  if (normalizedLang) {
    preferenceList.push(normalizedLang);
    if (langPrimary && langPrimary !== normalizedLang) preferenceList.push(langPrimary);
  }

  let chosenTrack = findTranscriptByPreference(catalog, preferenceList);
  let translationTarget: string | undefined;

  if (!chosenTrack && normalizedLang) {
    const translation = selectTranslationTarget(catalog, normalizedLang);
    if (!translation) {
      const available = getAvailableLanguages(catalog);
      const details = available.length > 0 ? available.join(', ') : 'none';
      throw new TranscriptFetchError(404, `Transcripts are not available in ${requestedLanguageLabel}. Available languages: ${details}`);
    }
    chosenTrack = translation.track;
    translationTarget = translation.targetLanguageCode;
  }

  if (!chosenTrack) {
    const manualFallback = catalog.manual.values().next().value as TranscriptTrack | undefined;
    const generatedFallback = catalog.generated.values().next().value as TranscriptTrack | undefined;
    chosenTrack = manualFallback || generatedFallback;
  }

  if (!chosenTrack) throw new TranscriptFetchError(404, 'Failed to resolve a valid transcript track.');

  let transcriptUrl = chosenTrack.url;
  if (translationTarget) transcriptUrl += `&tlang=${encodeURIComponent(translationTarget)}`;

  const transcriptRes = await fetchWithCookies(transcriptUrl, cookieJar, {
    headers: {
      'accept-language': acceptLang,
      'user-agent': YT_USER_AGENT,
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
    else if (path === '/tiff-viewer' || path === '/tiff-viewer/') path = '/tiff-viewer.html';
    else if (path === '/actuary' || path === '/actuary/') path = '/actuary.html';
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

    if (path.endsWith('vendor/utif.js')) return loadStaticAsset('vendor/utif.js', 'application/javascript; charset=utf-8');

    // Fallback to bundled HTML (tests/dev) if assets binding unavailable
    if (path.endsWith('markdown.html')) return loadHtml('markdown.html');
    if (path.endsWith('euler.html')) return loadHtml('euler.html');
    if (path.endsWith('pastebin.html')) return loadHtml('pastebin.html');
    if (path.endsWith('date.html')) return loadHtml('date.html');
    if (path.endsWith('llm-cost.html')) return loadHtml('llm-cost.html');
    if (path.endsWith('yt-transcript.html')) return loadHtml('yt-transcript.html');
    if (path.endsWith('tiff-viewer.html')) return loadHtml('tiff-viewer.html');
    if (path.endsWith('actuary.html')) return loadHtml('actuary.html');
    if (path.endsWith('index.html')) return loadHtml('index.html');

    return new Response('Not found', { status: 404 });
  },
} satisfies ExportedHandler<Env>;
