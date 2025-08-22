# Web Tools

A minimal Cloudflare Worker that serves a small suite of browser tools.

## Tools
- Markdown Preview (`/markdown`)
  - GitHub‑flavored Markdown via `marked`.
  - MathJax for inline `$...$` and block `$$...$$`.
  - Sanitized output with `DOMPurify`.
  - Dual‑pane editor/preview, theme toggle with persistence.
  - Tabs with rename/new/delete stored in `localStorage`.
  - Syntax highlighting via Highlight.js (full build) with language alias normalization and dark/light theme swapping.
  - Copy rendered HTML to clipboard.

- Euler Preview (`/euler`)
  - Preview Project Euler forum posts (BBCode + TeX).
  - Supported tags include `[b] [i] [s] [sup] [sub] [url] [img] [quote] [collapse] [list] [*] [hide] [r] [g] [h1] [h2] [center] [right]`.
  - Code blocks: `[code]...[/code]` or `[code=lang]...[/code]` with options `*` to disable highlight and `?` to force auto-detect (e.g. `[code=js]`, `[code=py*]`, `[code=?]`).
  - MathJax for `$...$` and `$$...$$`.
  - Tabs with rename/new/delete stored in `localStorage`.
  - Syntax highlighting via Highlight.js with language alias normalization and dark/light theme swapping.

Both tools include a Home button in the header to return to `/`.

- Pastebin (`/pastebin`)
  - Create and share text snippets.
  - Visibility options: `public` (listed) or `unlisted` (hidden from lists, accessible by link).
  - Auth via Google OAuth; stores users, sessions, and pastes in Cloudflare D1.
  - Not signed in or not allowed: pastes are saved in your browser’s localStorage (local mode). Local pastes are only visible in that browser/device; you can open them via `#local=<id>` in the URL.
  - Public listing at `/pastebin` shows recent public pastes; your pastes appear after sign-in.
  - Direct links like `/pastebin/p/abcd1234` open a read-only view.

## Routes
- `/` — Tools index page with tiles.
- `/markdown` — Markdown Preview.
- `/euler` — Euler Preview (Project Euler forum flavor).
 - `/pastebin` — Pastebin UI (create, list, login).
 - `/pastebin/p/:id` — View a specific paste (public or unlisted).
 - API: `/api/pastebin/*`, `/api/auth/*`, OAuth: `/auth/google/*`.

## Project Structure
- `src/index.ts` — Worker entry; routes and serves static assets from `public` via the `ASSETS` binding. Falls back to bundled reads in tests/dev.
- `public/index.html` — Index page.
- `public/markdown.html` — Markdown Preview page (Marked + DOMPurify + MathJax, tabs, Highlight.js with theme swap, copy button).
- `public/euler.html` — Euler Preview page (BBCode → HTML, MathJax, tabs, Highlight.js with theme swap).
 - `public/pastebin.html` — Pastebin UI.
- `wrangler.jsonc` — Wrangler config with assets binding enabled.
 - `migrations/0001_pastebin.sql` — D1 tables for users, sessions, pastes.
- `test/index.spec.ts` — Basic unit/integration tests.

## Development
- Dev server: `npm run dev` then open `http://localhost:8787/`.
- Tests: `npm test`
- Deploy: `npm run deploy`

If you change static HTML in `public/`, no Worker code changes are required.

## Pastebin Setup
1. Create a D1 database and bind it:
   - In `wrangler.jsonc`, set `d1_databases[0].database_id` to your D1 id (or use an env binding).
   - Run migrations: `wrangler d1 migrations apply web_tools_db` (or your database name).
2. Configure Google OAuth:
   - Create OAuth 2.0 Client (Web) in Google Cloud Console.
   - Authorized redirect URI: `https://YOUR_DOMAIN/auth/google/callback`
   - Set vars/secrets:
     - `wrangler secret put GOOGLE_CLIENT_SECRET`
     - `wrangler kv:namespace` not required.
     - In `wrangler.jsonc` `vars`, set `GOOGLE_CLIENT_ID` and `OAUTH_REDIRECT_URL`.
     - Optional: `SESSION_COOKIE_NAME` (defaults to `wt_session`).
3. Dev: ensure your dev URL’s redirect matches (use `--local-protocol=https` or a tunnel if needed).

Security notes:
- Sessions use random tokens stored in D1 and set as HttpOnly, Secure, SameSite=Lax cookies.
- Only `public` pastes appear in listings; `unlisted` require the direct link.
 - When not signed in or not allowed, pastes are saved to `localStorage` only and cannot be shared across devices. View a local paste by opening `/pastebin#local=<id>` on the same browser.

## Notes
- MathJax inline delimiters are restricted to `$...$` to avoid conflicts with literal parentheses in text and links; display math supports `$$...$$` and `\[...\]`.
- Output HTML is sanitized before insertion. Be cautious if you change the sanitization step.

## License
MIT — see [LICENSE.md](LICENSE.md).
