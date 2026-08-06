function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export function protectMarkdownMath(markdown) {
  const source = String(markdown || '');
  const snippets = [];
  let tokenPrefix = 'WTMATHPLACEHOLDER';

  while (source.includes(tokenPrefix)) tokenPrefix += 'X';

  const protectedMarkdown = source.replace(/\\\[[\s\S]*?\\\]|\\\([\s\S]*?\\\)/g, (value) => {
    const token = `${tokenPrefix}${snippets.length}END`;
    snippets.push({ token, value });
    return token;
  });

  return {
    markdown: protectedMarkdown,
    restore(html) {
      let restored = String(html || '');
      for (const snippet of snippets) {
        restored = restored.replaceAll(snippet.token, escapeHtml(snippet.value));
      }
      return restored;
    },
  };
}
