import { getCookies, setCookie } from './utils/cookies';
import { badRequest, json } from './utils/http';
import { urlSafeRandom } from './utils/random';
import type { Bindings, HandlerResult } from './types';

export async function getSessionUser(
  req: Request,
  env: Bindings,
): Promise<{ id: string; email?: string; name?: string; picture?: string } | null> {
  const cookieName = env.SESSION_COOKIE_NAME || 'wt_session';
  const cookies = getCookies(req);
  const token = cookies[cookieName];
  if (!token) return null;
  const row = await env.DB.prepare(
    'SELECT u.id, u.email, u.name, u.picture FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?',
  )
    .bind(token)
    .first();
  if (!row) return null;
  return row as any;
}

export async function requireUser(req: Request, env: Bindings): Promise<{ id: string; email?: string } | Response> {
  const user = await getSessionUser(req, env);
  if (!user) return new Response('Unauthorized', { status: 401 });
  return user;
}

export function isAllowedEmail(email?: string | null): boolean {
  return (email || '').toLowerCase() === 'bruce.hart@gmail.com';
}

export async function requireAllowedUser(
  req: Request,
  env: Bindings,
): Promise<{ id: string; email?: string } | Response> {
  const u = await getSessionUser(req, env);
  if (!u) return new Response('Unauthorized', { status: 401 });
  if (!isAllowedEmail(u.email || '')) return new Response('Forbidden', { status: 403 });
  return u;
}

export async function handleAuthRoutes(
  request: Request,
  env: Bindings,
  url: URL,
): Promise<HandlerResult> {
  const path = url.pathname;

  if (path === '/api/auth/me' && request.method === 'GET') {
    const user = await getSessionUser(request, env);
    return json({ loggedIn: !!user, user, allowed: !!(user && isAllowedEmail(user.email || '')) });
  }

  if (path === '/api/auth/logout' && request.method === 'POST') {
    const cookieName = env.SESSION_COOKIE_NAME || 'wt_session';
    const token = getCookies(request)[cookieName];
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    const res = json({ ok: true });
    setCookie(res, cookieName, '', { path: '/', maxAge: 0, httpOnly: true, secure: true, sameSite: 'Lax' });
    return res;
  }

  if (path === '/auth/google/login' && request.method === 'GET') {
    const clientId = env.GOOGLE_CLIENT_ID;
    const redirect = env.OAUTH_REDIRECT_URL;
    if (!clientId || !redirect) return badRequest('Google OAuth not configured', 500);
    const state = urlSafeRandom(16);
    const oauthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    oauthUrl.searchParams.set('client_id', clientId);
    oauthUrl.searchParams.set('redirect_uri', redirect);
    oauthUrl.searchParams.set('response_type', 'code');
    oauthUrl.searchParams.set('scope', 'openid email profile');
    oauthUrl.searchParams.set('state', state);
    const res = new Response(null, { status: 302, headers: { location: oauthUrl.toString() } });
    setCookie(res, 'oauth_state', state, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 600,
    });
    return res;
  }

  if (path === '/auth/google/callback' && request.method === 'GET') {
    const state = url.searchParams.get('state') || '';
    const code = url.searchParams.get('code') || '';
    const cookieState = getCookies(request)['oauth_state'];
    if (!code || !state || !cookieState || state !== cookieState) return badRequest('Invalid state');
    const clientId = env.GOOGLE_CLIENT_ID || '';
    const clientSecret = (env as any).GOOGLE_CLIENT_SECRET as string | undefined;
    const redirect = env.OAUTH_REDIRECT_URL || '';
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
    await env.DB.prepare(
      'INSERT INTO users (id, email, name, picture) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET email=excluded.email, name=excluded.name, picture=excluded.picture',
    )
      .bind(sub, email, name, picture)
      .run();
    const token = urlSafeRandom(24);
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toUTCString();
    await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, sub, expiresAt).run();
    const res = new Response(null, { status: 302, headers: { location: '/pastebin' } });
    setCookie(res, 'oauth_state', '', { path: '/', maxAge: 0 });
    setCookie(res, env.SESSION_COOKIE_NAME || 'wt_session', token, {
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 * 7,
    });
    return res;
  }

  return null;
}
