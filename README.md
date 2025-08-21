# Web Tools

A minimal Cloudflare Worker that serves a small suite of browser tools. Currently includes a Markdown → HTML viewer with MathJax support.

## Features
- Markdown rendering: GitHub‑flavored via `marked`.
- MathJax: Inline `$...$` and block `$$...$$` equations.
- Sanitization: Output sanitized with `DOMPurify`.
- UX: Dual‑pane editor/preview, dark header, bordered panes.
- Extras: Theme toggle (light/dark) with persistence, “Copy HTML” button.

## Routes
- `/` — Tools index page with tiles.
- `/markdown` — Markdown viewer.

## Project Structure
- `src/index.ts` — Worker entry; routes and serves static assets from `public` via the `ASSETS` binding. Falls back to bundled reads in tests/dev.
- `public/index.html` — Index page.
- `public/markdown.html` — Markdown viewer page (Marked + DOMPurify + MathJax, theme toggle, copy button).
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
