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

  // Some Markdown producers emit display math with bare bracket lines instead
  // of MathJax's escaped \[...\] delimiters. Normalize that form before Marked
  // can interpret the TeX backslashes as Markdown escapes.
  const normalizedSource = source.replace(
    /^[ \t]*\[[ \t]*\r?\n([\s\S]*?)^[ \t]*\][ \t]*(?=\r?$)/gm,
    (_value, expression) => `\\[\n${expression}\\]`,
  );

  const protectedMarkdown = normalizedSource.replace(/\\\[[\s\S]*?\\\]|\\\([\s\S]*?\\\)/g, (value) => {
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
