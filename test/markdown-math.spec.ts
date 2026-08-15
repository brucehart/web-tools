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

	it('normalizes bare bracket lines around display math', () => {
		const source = String.raw`For node (i), the state is approximately

  [
  c_i=
  [\underbrace{\delta t_i,\dot{\delta t}_i}_{\text{clock}},
  \underbrace{\phi_i,\delta f_i}_{\text{carrier}},
  \underbrace{p_i,v_i,\delta\theta_i}_{\text{pose}},
  \underbrace{g_i}_{\text{RF gain}}].
  ]

## 1. Clock offset and drift

Model the local clock as

[
t_i^{local}(t)=t+\delta t_i+\dot{\delta t}_i(t-t_0)+\text{noise}.
]`;

		const protectedMath = protectMarkdownMath(source);
		const restored = protectedMath.restore(marked.parse(protectedMath.markdown));

		expect(restored.match(/\\\[/g)).toHaveLength(2);
		expect(restored.match(/\\\]/g)).toHaveLength(2);
		expect(restored).toContain(String.raw`\underbrace{\delta t_i,\dot{\delta t}_i}_{\text{clock}}`);
		expect(restored).toContain(String.raw`t_i^{local}(t)=t+\delta t_i`);
		expect(restored).toContain('<h2>1. Clock offset and drift</h2>');
		expect(restored).not.toContain('WTMATHPLACEHOLDER');
	});

	it('does not treat brackets within prose as math delimiters', () => {
		const source = 'Keep [this label] and [this link](https://example.com) as Markdown.';
		const protectedMath = protectMarkdownMath(source);
		const restored = protectedMath.restore(marked.parse(protectedMath.markdown));

		expect(restored).toContain('[this label]');
		expect(restored).toContain('<a href="https://example.com">this link</a>');
		expect(restored).not.toContain(String.raw`\[`);
	});
});
