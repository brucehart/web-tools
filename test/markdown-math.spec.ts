import { describe, expect, it } from 'vitest';
import { marked } from 'marked';
import { protectMarkdownMath } from '../public/shared/markdown-math.js';

describe('Markdown math rendering', () => {
	it('preserves bracket-delimited display math through marked', () => {
		const source = String.raw`For unchanged frequency and antennas, the path-loss difference is

\[
\Delta L_{\mathrm{FS}}
=20\log_{10}\!\left(\frac{120}{70}\right)
\approx 4.68\ \mathrm{dB}.
\]`;

		const parsedWithoutProtection = marked.parse(source);
		expect(parsedWithoutProtection).not.toContain(String.raw`\[`);

		const protectedMath = protectMarkdownMath(source);
		const restored = protectedMath.restore(marked.parse(protectedMath.markdown));

		expect(restored).toContain(String.raw`\[`);
		expect(restored).toContain(String.raw`\Delta L_{\mathrm{FS}}`);
		expect(restored).toContain(String.raw`\]`);
		expect(restored).not.toContain('WTMATHPLACEHOLDER');
	});

	it('preserves parenthesis-delimited inline math through marked', () => {
		const source = String.raw`The margin is \(4.68\ \mathrm{dB}\).`;
		const protectedMath = protectMarkdownMath(source);
		const restored = protectedMath.restore(marked.parse(protectedMath.markdown));

		expect(restored).toContain(String.raw`\(4.68\ \mathrm{dB}\)`);
	});
});
