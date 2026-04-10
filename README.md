# Web Tools

A Cloudflare Worker that serves a suite of browser-based developer and utility tools. Most pages run entirely in the browser; account-backed features use Cloudflare D1 plus Google OAuth.

## Tools

- Markdown Viewer (`/markdown`)
  - GitHub-flavored Markdown via `marked`, sanitized with `DOMPurify`, and rendered with MathJax.
  - Syntax highlighting via Highlight.js with light/dark theme swapping.
  - Multi-document tabs stored locally or synced to D1 for signed-in users via `/api/pages/*`.
  - Copy rendered HTML to the clipboard.

- Euler Preview (`/euler`)
  - Preview Project Euler forum posts with BBCode, TeX, and Highlight.js code blocks.
  - Supports forum-style tags such as headings, quote/list/collapse blocks, alignment, and `[code=lang]`.
  - Multi-document tabs stored locally or synced to D1 for signed-in users via `/api/pages/*`.
  - Copy rendered HTML to the clipboard.

- Pastebin (`/pastebin`)
  - Create snippets with `public`, `unlisted`, or `private` visibility.
  - Public feed plus a signed-in per-user list; direct links open at `/pastebin/p/:id`.
  - Guest mode stores drafts in `localStorage` when you are not signed in.

- Text Diff (`/diff`)
  - Compare original and changed text line by line with git-style output.
  - Shows added, removed, changed, and unchanged counts.
  - Includes swap, clear, large-input warnings, and `localStorage` persistence.

- Base64 Encoder/Decoder (`/base64`)
  - Encode files to raw Base64 and data URLs via drag and drop or a file picker.
  - Decode raw Base64 or data URLs back into downloadable files with configurable filename and MIME type.
  - Includes UTF-8 text encode/decode helpers and clipboard copy actions.

- Image Editor (`/image-editor`)
  - Load images from file picker, drag and drop, or clipboard paste.
  - Zoom, pan, rotate in 90 degree steps, crop interactively, and reset edits.
  - Export PNG, JPG, or WEBP with quality controls where applicable, then download or copy the edited image.

- URL Encode/Decode (`/url-encode-decode`)
  - Encode and decode URL components in the browser.
  - Move output back into input for multi-level transforms.
  - Includes swap, clear, and clipboard copy helpers.

- Data Format Converter (`/format-tools`)
  - Convert between JSON, YAML, TOML, and CSV.
  - Validate parsed output against JSON Schema with Ajv 2020.
  - Compare source and converted content with text or semantic diff views.
  - Persists the last inputs and settings in `localStorage`.

- CSV Viewer & Editor (`/csv-editor`)
  - Import CSV with or without header rows into an Excel-like grid.
  - Add/delete rows and columns, sort/filter columns, and copy selected cells.
  - Export CSV with comma, semicolon, or tab delimiters, or copy TSV for Sheets/Excel.
  - Persists the grid in `localStorage` and warns on large datasets.

- Boards (`/boards`)
  - Signed-in, D1-backed Trello-style boards with draggable lists and cards.
  - Cards support Markdown notes plus up to three attached images.
  - Includes inline editing for board and list names, card detail modals, and cross-device sync.

- To-Do List (`/todo`)
  - Signed-in, D1-backed task manager with priorities, categories, due dates, and descriptions.
  - Stats cards plus filters for status, priority, and category.
  - Supports create, edit, toggle, delete, and cross-device sync.

- Daily Goal Tracker (`/goals`)
  - Signed-in, D1-backed goal tracker with one card per goal and a current-month calendar.
  - Each day cycles through `complete`, `partial`, `missed`, or empty state.
  - Designed for quick daily habit tracking with immediate sync.

- Date Calculator (`/date`)
  - Compute date differences in days, weeks, and calendar year/month/day terms.
  - Add or subtract days, weeks, months, or years from a base date.
  - Includes a custom date picker plus "Set to Today" shortcuts.

- LLM Cost Calculator (`/llm-cost`)
  - Parse token usage dumps, including cached and reasoning tokens.
  - Price input, cached input, output, and reasoning tokens per token, per 1K, or per 1M.
  - Save model pricing profiles locally and copy a cost summary.

- Actuary Calculator (`/actuary`)
  - XKCD-style group mortality odds using Social Security actuarial tables.
  - Accepts multiple ages with optional gender suffixes and an optional horizon.
  - Reports 5/50/95% timing plus horizon probabilities.

- YouTube Transcript (`/yt-transcript`)
  - Fetch transcripts for public YouTube videos, with optional translation when available.
  - Accepts full URLs, short URLs, or bare video IDs.
  - Shows normalized segments plus full transcript text with copy support.

- TIFF Viewer (`/tiff-viewer`)
  - Decode TIFF images locally from file input or pasted Base64/data URLs using bundled `UTIF.js`.
  - Toggle, solo, and recolor channels for multi-channel images.
  - Zoom in/out, fit to width, and inspect large images without server-side processing.

All tools use the shared header/theme assets in `public/shared`, and the home page at `/` provides searchable tiles for the full suite.

## Routes

### Tool pages

- `/` - searchable tools index.
- `/markdown` - Markdown Viewer.
- `/euler` - Euler Preview.
- `/pastebin` - Pastebin UI.
- `/diff` - Text Diff.
- `/base64` - Base64 Encoder/Decoder.
- `/image-editor` - Image Editor.
- `/url-encode-decode` - URL Encode/Decode.
- `/format-tools` - Data Format Converter.
- `/csv-editor` - CSV Viewer & Editor.
- `/boards` - Boards.
- `/todo` - To-Do List.
- `/goals` - Daily Goal Tracker.
- `/date` - Date Calculator.
- `/llm-cost` - LLM Cost Calculator.
- `/actuary` - Actuary Calculator.
- `/yt-transcript` - YouTube Transcript.
- `/tiff-viewer` - TIFF Viewer.

### Data and auth routes

- `/pastebin/p/:id` - view a specific paste.
- `/api/auth/me` - current session status.
- `/api/auth/logout` - log out the current session.
- `/auth/google/login` - start Google OAuth.
- `/auth/google/callback` - Google OAuth callback.
- `/api/pastebin/create`, `/api/pastebin/mine`, `/api/pastebin/public`, `/api/pastebin/get`, `/api/pastebin/delete`
- `/api/pages/create`, `/api/pages/list`, `/api/pages/get`, `/api/pages/update`, `/api/pages/delete`
- `/api/boards/list`, `/api/boards/create`, `/api/boards/get`, `/api/boards/update`, `/api/boards/delete`
- `/api/boards/lists/create`, `/api/boards/lists/update`, `/api/boards/lists/delete`, `/api/boards/lists/reorder`
- `/api/boards/cards/create`, `/api/boards/cards/update`, `/api/boards/cards/delete`, `/api/boards/cards/reorder`, `/api/boards/cards/move`
- `/api/boards/cards/images/add`, `/api/boards/cards/images/delete`
- `/api/todo/create`, `/api/todo/list`, `/api/todo/get`, `/api/todo/update`, `/api/todo/toggle`, `/api/todo/delete`
- `/api/goals/create`, `/api/goals/list`, `/api/goals/delete`, `/api/goals/entry`
- `/api/yt-transcript`
- `/api/_internal/seed` - internal test helper.

## Project Structure

- `src/index.ts` - Worker entry; dispatches auth, API, dynamic paste, and static tool routes.
- `src/static.ts` - pretty-route mapping for all HTML tool pages in `public/`.
- `src/auth.ts` - Google OAuth, session lookup, and logout handling.
- `src/boards.ts` - Boards API for boards, lists, cards, drag/drop ordering, and image attachments.
- `src/pastebin.ts` - Pastebin API and `/pastebin/p/:id` page handling.
- `src/pages.ts` - D1-backed saved pages for Markdown Viewer and Euler Preview.
- `src/todo.ts` - To-Do List API.
- `src/goals.ts` - Daily Goal Tracker API.
- `src/routes/transcript.ts` and `src/yt-transcript.ts` - YouTube transcript endpoint and fetch logic.
- `public/` - one HTML page per tool, plus `public/shared/` for shared UI assets.
- `public/vendor/dompurify/purify.min.js` - bundled DOMPurify used by the Boards tool.
- `public/vendor/utif.js` - bundled TIFF decoder used by the viewer.
- `migrations/0001_pastebin.sql` through `migrations/0007_boards.sql` - D1 schema for users/sessions, pastebin, todos, goals, synced editor pages, and boards.
- `test/index.spec.ts` - worker tests with Vitest and the Cloudflare Workers pool.
- `wrangler.jsonc` - Wrangler config and bindings.

## Development

- Install dependencies: `npm install`
- Start local dev server: `npm run dev` or `npm start`
- Run tests: `npm test`
- Deploy: `npm run deploy`
- Refresh generated Cloudflare types after binding changes: `npm run cf-typegen`

If you change only static HTML in `public/`, you usually do not need Worker code changes unless the route surface or backing APIs change.

## Account-Backed Features Setup

The following features require D1 and Google OAuth:

- Pastebin account storage and private/unlisted sharing
- Markdown Viewer and Euler Preview synced pages
- Boards
- To-Do List
- Daily Goal Tracker

Everything else works without D1 or OAuth.

1. Create a D1 database and bind it in `wrangler.jsonc`.
2. Apply the migrations:
   - `wrangler d1 migrations apply web_tools_db`
   - Replace `web_tools_db` with your actual database binding name if needed.
3. Configure Google OAuth:
   - Create an OAuth 2.0 Web application in Google Cloud Console.
   - Add an authorized redirect URI: `https://YOUR_DOMAIN/auth/google/callback`
   - Set `GOOGLE_CLIENT_ID` and `OAUTH_REDIRECT_URL` in `wrangler.jsonc` `vars`.
   - Set the client secret with `wrangler secret put GOOGLE_CLIENT_SECRET`.
   - Optionally set `SESSION_COOKIE_NAME` (defaults to `wt_session`).
4. For local development, make sure the dev callback URL matches your configured redirect URI. Using HTTPS locally or a tunnel is usually easiest for OAuth testing.

Security notes:

- Sessions use random tokens stored in D1 and are set as `HttpOnly`, `Secure`, `SameSite=Lax` cookies.
- Only `public` pastes appear in the public listing.
- `unlisted` and `private` pastes do not appear in public listings; `private` pastes are owner-only.
- Guest paste mode uses `localStorage`, so those drafts stay on the same browser/device.

## Notes

- MathJax inline delimiters are restricted to `$...$` to avoid conflicts with ordinary text. Display math supports `$$...$$` and `\[...\]`.
- Rendered HTML is sanitized before insertion. Be careful if you change the sanitization path.

## License

MIT - see [LICENSE.md](LICENSE.md).
