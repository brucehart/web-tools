import { fetchYouTubeTranscript, TranscriptFetchError } from '../yt-transcript';
import { json, readJson } from '../utils/http';
import type { Bindings, HandlerResult } from '../types';

export async function handleTranscriptApi(
  request: Request,
  _env: Bindings,
  _url: URL,
): Promise<HandlerResult> {
  if (request.method !== 'POST') return null;
  const url = new URL(request.url);
  if (url.pathname !== '/api/yt-transcript') return null;

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
