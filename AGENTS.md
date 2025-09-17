# Repository Guidelines

## Project Structure & Module Organization
Runtime logic lives in `src/index.ts`, the Cloudflare Worker entry that dispatches static routes and APIs. Browser-facing UIs are plain HTML/JS assets in `public/`; keep any shared client helpers alongside the page that uses them. Database migrations are under `migrations/` and should be versioned sequentially. Tests for worker behaviour sit in `test/` with Vitest setup and a dedicated `tsconfig.json`. Built bundles go to `dist/`; treat it as generated output.

## Build, Test, and Development Commands
Run `npm install` once to sync dependencies. Use `npm run dev` (alias `npm start`) to launch Wrangler with live reload at `http://localhost:8787`. Execute `npm test` to run Vitest in the Cloudflare Workers pool. Deploy with `npm run deploy`, which wraps `wrangler deploy` against the environment configured in `wrangler.jsonc`. Update type bindings after editing `wrangler.jsonc` by running `npm run cf-typegen`.

## Coding Style & Naming Conventions
The project is strict TypeScript; prefer explicit types over implicit `any`. Stick to 2-space indentation, single quotes, and trailing commas where TypeScript’s formatter inserts them. Export top-level helpers instead of expanding the worker handler. Name request handlers and utilities descriptively (`handlePastebinRequest`, `parseTranscriptXml`) and keep file names lowercase with hyphens only when multiple words are needed. Document non-obvious logic with brief line comments.

## Testing Guidelines
Vitest with `@cloudflare/vitest-pool-workers` powers integration-style worker tests. Place new specs in `test/*.spec.ts`, mirroring the route or helper name. Use `describe` blocks keyed to the public API (`describe('POST /api/pastebin')`). Mock bindings via `envBinding` helpers rather than stubbing globals directly. Guard new behaviour with assertions on status codes, headers, and payload shape. Aim to keep or raise existing coverage; add regression tests when patching bugs.

## Commit & Pull Request Guidelines
Commit messages follow short, imperative subjects (`Add transcript translation toggle`, `Fix pastebin migrations`) with optional scopes like `chore:` when helpful. Group related changes per commit to simplify review. Pull requests should outline intent, mention affected routes or bindings, and call out migration or secret updates. Include test evidence (`npm test`) and, when UI changes occur, attach before/after screenshots of the relevant HTML page.

## Environment & Secrets
Wrangler manages bindings; sync local `.dev.vars` with `wrangler.toml` equivalents before running secure endpoints. Store OAuth secrets via `wrangler secret put` and reference them through the typed `Env`. For D1 changes, update `wrangler.jsonc` and run `wrangler d1 migrations apply web_tools_db` (replace with your database name) to keep environments aligned.
