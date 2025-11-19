export function json(data: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(data), {
    headers: { 'content-type': 'application/json; charset=utf-8' },
    ...init,
  });
}

export function badRequest(message: string, status = 400): Response {
  return new Response(message, { status });
}

export async function readJson<T = Record<string, unknown>>(req: Request): Promise<T> {
  const ct = req.headers.get('content-type') || '';
  if (ct.includes('application/json')) return (await req.json()) as T;
  const text = await req.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    return {} as T;
  }
}
