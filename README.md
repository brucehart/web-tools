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

## Routes
- `/` — Tools index page with tiles.
- `/markdown` — Markdown Preview.
- `/euler` — Euler Preview (Project Euler forum flavor).

## Project Structure
- `src/index.ts` — Worker entry; routes and serves static assets from `public` via the `ASSETS` binding. Falls back to bundled reads in tests/dev.
- `public/index.html` — Index page.
- `public/markdown.html` — Markdown Preview page (Marked + DOMPurify + MathJax, tabs, Highlight.js with theme swap, copy button).
- `public/euler.html` — Euler Preview page (BBCode → HTML, MathJax, tabs, Highlight.js with theme swap).
- `wrangler.jsonc` — Wrangler config with assets binding enabled.
- `test/index.spec.ts` — Basic unit/integration tests.

## Development
- Dev server: `npm run dev` then open `http://localhost:8787/`.
- Tests: `npm test`
- Deploy: `npm run deploy`

If you change static HTML in `public/`, no Worker code changes are required.

## Notes
- MathJax inline delimiters are restricted to `$...$` to avoid conflicts with literal parentheses in text and links; display math supports `$$...$$` and `\[...\]`.
- Output HTML is sanitized before insertion. Be cautious if you change the sanitization step.

## License
MIT — see [LICENSE.md](LICENSE.md).

