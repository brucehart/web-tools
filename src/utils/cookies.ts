export function getCookies(req: Request): Record<string, string> {
  const header = req.headers.get('cookie') || '';
  const out: Record<string, string> = {};
  header.split(/;\s*/).forEach((part) => {
    if (!part) return;
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = decodeURIComponent(part.slice(0, idx).trim());
    const val = decodeURIComponent(part.slice(idx + 1).trim());
    out[key] = val;
  });
  return out;
}

export function setCookie(
  res: Response,
  name: string,
  value: string,
  attrs: Record<string, string | number | boolean> = {},
): void {
  const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`];
  if (attrs.path !== undefined) parts.push(`Path=${attrs.path}`);
  if (attrs.httpOnly !== false) parts.push('HttpOnly');
  if (attrs.sameSite !== undefined) parts.push(`SameSite=${attrs.sameSite}`);
  if (attrs.secure !== false) parts.push('Secure');
  if (attrs.maxAge !== undefined) parts.push(`Max-Age=${attrs.maxAge}`);
  if (attrs.expires !== undefined) parts.push(`Expires=${attrs.expires}`);
  res.headers.append('Set-Cookie', parts.join('; '));
}
