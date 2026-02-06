(function() {
  const THEME_KEY = 'wt_theme';
  const root = document.documentElement;

  const TOOLS = [
    { id: 'home', title: 'Home', href: '/' },
    { id: 'pastebin', title: 'Pastebin', href: '/pastebin' },
    { id: 'yt-transcript', title: 'YouTube Transcript', href: '/yt-transcript' },
    { id: 'markdown', title: 'Markdown Viewer', href: '/markdown' },
    { id: 'euler', title: 'Euler Preview', href: '/euler' },
    { id: 'date', title: 'Date Calculator', href: '/date' },
    { id: 'llm-cost', title: 'LLM Cost', href: '/llm-cost' },
    { id: 'tiff-viewer', title: 'TIFF Viewer', href: '/tiff-viewer' },
    { id: 'todo', title: 'To-Do', href: '/todo' },
    { id: 'goals', title: 'Goals', href: '/goals' },
    { id: 'actuary', title: 'Actuary', href: '/actuary' },
  ];

  function preferredTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light';
  }

  function applyTheme(theme) {
    const next = theme === 'dark' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    localStorage.setItem(THEME_KEY, next);
    const btn = document.getElementById('wtToggleTheme');
    if (btn) {
      btn.setAttribute('aria-label', next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
      btn.title = next === 'dark' ? 'Light theme' : 'Dark theme';
      btn.textContent = next === 'dark' ? 'Light' : 'Dark';
    }
    window.dispatchEvent(new CustomEvent('wt-theme-change', { detail: { theme: next } }));
  }

  function renderHeader() {
    const body = document.body;
    if (!body) return;

    body.classList.add('wt');

    const toolId = body.getAttribute('data-wt-tool') || '';
    const toolTitle = body.getAttribute('data-wt-title') || document.title || 'Web Tools';

    let header = document.querySelector('.wt-header');
    if (!header) {
      header = document.createElement('div');
      header.className = 'wt-header';
      header.setAttribute('role', 'banner');
      body.insertBefore(header, body.firstChild);
    }

    header.innerHTML = [
      '<div class="wt-header-inner">',
      '  <div class="wt-brand">',
      '    <a href="/" class="wt-logo-link" aria-label="Web Tools home" title="Web Tools">',
      '      <svg class="wt-logo" viewBox="0 0 64 64" role="img" aria-hidden="true" focusable="false">',
      '        <defs>',
      '          <linearGradient id="wtG" x1="0" y1="0" x2="1" y2="1">',
      '            <stop offset="0" stop-color="currentColor" stop-opacity="0.95" />',
      '            <stop offset="1" stop-color="currentColor" stop-opacity="0.55" />',
      '          </linearGradient>',
      '        </defs>',
      '        <path d="M10 20c0-6 5-10 12-10h20c7 0 12 4 12 10v24c0 6-5 10-12 10H22c-7 0-12-4-12-10V20z" fill="none" stroke="url(#wtG)" stroke-width="3.2" />',
      '        <path d="M18 24l6 18 8-14 8 14 6-18" fill="none" stroke="currentColor" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round" />',
      '        <circle cx="18" cy="24" r="2.2" fill="currentColor" />',
      '        <circle cx="46" cy="24" r="2.2" fill="currentColor" />',
      '      </svg>',
      '      <span class="wt-sr-only">Web Tools</span>',
      '    </a>',
      `    <div class="wt-toolname" title="${escapeHtml(toolTitle)}">${escapeHtml(toolTitle)}</div>`,
      '  </div>',
      '  <div class="wt-spacer" aria-hidden="true"></div>',
      '  <div class="wt-actions">',
      '    <a class="wt-btn wt-btn-ghost" href="/" title="Home">Home</a>',
      '    <button id="wtToggleTheme" class="wt-btn" type="button" title="Toggle theme">Theme</button>',
      '    <div id="wtHeaderExtraMount" class="wt-extra"></div>',
      '  </div>',
      '</div>',
    ].join('\n');

    const extraTpl = document.getElementById('wtHeaderExtra');
    const extraMount = document.getElementById('wtHeaderExtraMount');
    if (extraTpl && extraMount && extraTpl instanceof HTMLTemplateElement) {
      extraMount.replaceChildren(extraTpl.content.cloneNode(true));
    }

    // Keep the tool title visible in the header; do not force document.title if page wants it.
    const toolnameEl = header.querySelector('.wt-toolname');
    if (toolnameEl) toolnameEl.textContent = toolTitle;
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function init() {
    renderHeader();
    applyTheme(preferredTheme());
    document.getElementById('wtToggleTheme')?.addEventListener('click', () => {
      const cur = root.getAttribute('data-theme') || preferredTheme();
      applyTheme(cur === 'dark' ? 'light' : 'dark');
    });
  }

  window.WebTools = {
    init,
    applyTheme,
    preferredTheme,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
