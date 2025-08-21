/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

const INDEX_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Web Tools</title>
    <style>
      :root { color-scheme: light dark; }
      * { box-sizing: border-box; }
      html, body { height: 100%; margin: 0; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, sans-serif; }
      header { padding: 1rem; border-bottom: 1px solid #ddd; }
      h1 { margin: 0; font-size: 1.25rem; }
      .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 1rem; padding: 1rem; }
      .tile { display: block; border: 1px solid #ddd; border-radius: 10px; padding: 1rem; text-decoration: none; color: inherit; background: rgba(127,127,127,0.06); }
      .tile:hover { background: rgba(127,127,127,0.12); }
      .tile h2 { margin: 0 0 .5rem; font-size: 1.05rem; }
      .tile p { margin: 0; color: #555; }
      footer { padding: .75rem 1rem; border-top: 1px solid #ddd; font-size: .9rem; color: #666; }
    </style>
  </head>
  <body>
    <header>
      <h1>Web Tools</h1>
    </header>
    <main class="grid">
      <a class="tile" href="/markdown">
        <h2>Markdown Viewer</h2>
        <p>Paste Markdown and view formatted HTML with MathJax.</p>
      </a>
    </main>
    <footer>More tools coming soon.</footer>
  </body>
  </html>`;

const MARKDOWN_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Markdown to HTML Viewer</title>
    <style>
      :root { color-scheme: light dark; }
      * { box-sizing: border-box; }
      html, body { height: 100%; margin: 0; }
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, sans-serif; }
      header { padding: 0.75rem 1rem; border-bottom: 1px solid #ddd; }
      header h1 { margin: 0; font-size: 1.1rem; }
      .container { display: grid; grid-template-columns: 1fr 1fr; gap: 0; height: calc(100% - 48px); }
      .pane { height: 100%; }
      textarea { width: 100%; height: 100%; padding: 1rem; border: none; outline: none; resize: none; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 14px; line-height: 1.5; }
      #preview { overflow: auto; padding: 1rem; }
      #preview h1, #preview h2, #preview h3 { border-bottom: 1px solid #eaecef; padding-bottom: .3rem; }
      #preview pre { background: rgba(127,127,127,0.1); padding: .75rem; overflow: auto; border-radius: 6px; }
      #preview code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
      #preview table { border-collapse: collapse; }
      #preview table th, #preview table td { border: 1px solid #ddd; padding: .25rem .5rem; }
      .footer { font-size: .85rem; color: #666; padding: .5rem 1rem; border-top: 1px solid #ddd; }
      @media (max-width: 900px) { .container { grid-template-columns: 1fr; grid-auto-rows: 50vh 50vh; } }
    </style>

    <script>
      // MathJax v3 configuration
      // Use only $...$ for inline math to avoid conflicts with literal parentheses in text/links.
      window.MathJax = {
        tex: {
          inlineMath: [['$', '$']],
          displayMath: [['$$','$$'], ['\\\[', '\\\]']]
        },
        options: { skipHtmlTags: ['script','noscript','style','textarea','pre','code'] }
      };
    </script>
    <script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.7/dist/purify.min.js"></script>
    <script async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-chtml.js"></script>
  </head>
  <body>
    <header>
      <h1>Markdown → HTML (MathJax)</h1>
    </header>
    <div class="container">
      <section class="pane">
        <textarea id="input" placeholder="Paste Markdown here..."># Welcome

Type Markdown on the left and see HTML on the right.

- Supports GitHub-flavored Markdown
- Sanitizes output with DOMPurify
- Renders LaTeX via MathJax: $E=mc^2$

Block math:

$$
\\int_{-\\infty}^{\\infty} e^{-x^2} \\mathrm{d}x = \\sqrt{\\pi}
$$

        </textarea>
      </section>
      <section id="preview" class="pane"></section>
    </div>
    <div class="footer">Tip: Use $inline$ or $$block$$ for LaTeX.</div>

    <script>
      (function() {
        const input = document.getElementById('input');
        const preview = document.getElementById('preview');
        if (!input || !preview) return;

        // Configure marked for GFM and line breaks
        if (window.marked && typeof window.marked.setOptions === 'function') {
          window.marked.setOptions({ gfm: true, breaks: true });
        }

        const render = () => {
          const md = input.value || '';
          let raw = md;
          const mk = window.marked;
          if (mk) {
            if (typeof mk.parse === 'function') raw = mk.parse(md);
            else if (typeof mk === 'function') raw = mk(md);
          }
          const safe = window.DOMPurify ? window.DOMPurify.sanitize(raw) : raw;
          preview.innerHTML = safe;
          if (window.MathJax && window.MathJax.typesetPromise) {
            window.MathJax.typesetPromise([preview]).catch(() => {});
          }
        };

        input.addEventListener('input', render);
        // Initial render
        render();
      })();
    </script>
  </body>
  </html>`;

export default {
  async fetch(request, _env, _ctx): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/markdown' || path.startsWith('/markdown/')) {
      return new Response(MARKDOWN_HTML, {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
        },
      });
    }
    // Default to index page
    return new Response(INDEX_HTML, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
      },
    });
  },
} satisfies ExportedHandler<Env>;
