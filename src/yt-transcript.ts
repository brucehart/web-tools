const YT_WATCH_URL = 'https://www.youtube.com/watch';
const YT_PLAYER_URL = 'https://www.youtube.com/youtubei/v1/player';
const YT_USER_AGENT =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.83 Safari/537.36,gzip(gfe)';
const INNERTUBE_CONTEXT = Object.freeze({
  client: {
    clientName: 'ANDROID',
    clientVersion: '20.10.38',
  },
});

export class TranscriptFetchError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
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
    results.push({
      text,
      offset: Number.isFinite(offset) ? offset : 0,
      duration: Number.isFinite(duration) ? duration : 0,
    });
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
  return Array.from(new Set<string>([...catalog.manual.keys(), ...catalog.generated.keys()]));
}

function findTranscriptByPreference(
  catalog: TranscriptCatalog,
  preferences: string[],
): TranscriptTrack | undefined {
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

function selectTranslationTarget(
  catalog: TranscriptCatalog,
  desired: string,
): { track: TranscriptTrack; targetLanguageCode: string } | null {
  const normalizedDesired = desired.toLowerCase();
  const languagePrimary = normalizedDesired.split('-')[0] || normalizedDesired;
  const translation =
    catalog.translationLanguages.find((entry) => entry.languageCode === normalizedDesired) ||
    catalog.translationLanguages.find((entry) => entry.languageCode.split('-')[0] === languagePrimary);
  if (!translation) return null;
  const translatableSource = [...catalog.manual.values(), ...catalog.generated.values()].find(
    (track) => track.isTranslatable,
  );
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

export async function fetchYouTubeTranscript(
  source: string,
  language?: string,
): Promise<{ text: string; offset: number; duration: number }[]> {
  const videoId = extractVideoId(source);
  if (!videoId) throw new TranscriptFetchError(400, 'Unable to determine YouTube video ID.');
  const normalizedLang = (language || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '') || undefined;
  const requestedLanguageLabel = (language || '').trim() || normalizedLang || 'the requested language';
  const cookieJar: CookieJar = new Map<string, string>();
  const langPrimary = normalizedLang ? normalizedLang.split('-')[0] || normalizedLang : undefined;
  const acceptLang =
    normalizedLang && langPrimary ? `${normalizedLang},${langPrimary};q=0.9,en;q=0.8` : 'en-US,en;q=0.9';

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
      throw new TranscriptFetchError(
        404,
        `Transcripts are not available in ${requestedLanguageLabel}. Available languages: ${details}`,
      );
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
