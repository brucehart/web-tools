import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('GET /llm-cost', () => {
  it('serves current OpenAI frontier pricing presets', async () => {
    const response = await SELF.fetch('https://example.com/llm-cost');

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('text/html');

    const body = await response.text();
    expect(body).toContain('<title>LLM Cost Calculator</title>');
    expect(body).toContain("'gpt-5.6-sol': frontierPricing(5.00, 0.50, 6.25, 30.00)");
    expect(body).toContain("'gpt-5.6-terra': frontierPricing(2.00, 0.20, 2.50, 12.00)");
    expect(body).toContain("'gpt-5.6-luna': frontierPricing(0.20, 0.02, 0.25, 1.20)");
    expect(body).toContain("'gpt-5.5': frontierPricing(5.00, 0.50, 0, 30.00)");
    expect(body).toContain("'gpt-5.4-mini': frontierPricing(0.75, 0.075, 0, 4.50)");
    expect(body).toContain("'gpt-5.4-nano': frontierPricing(0.20, 0.02, 0, 1.25)");
    expect(body).toContain("'gpt-5.4-pro (long context)': frontierPricing(60.00, 0, 0, 270.00)");
    expect(body).toContain("'gpt-5.6-terra (long context)': frontierPricing(4.00, 0.40, 5.00, 18.00)");
    expect(body).toContain("'gpt-5.6-luna (long context)': frontierPricing(0.40, 0.04, 0.50, 1.80)");
    expect(body).toContain('id="cacheWriteTok"');
    expect(body).toContain('id="cacheWritePrice"');
    expect(body).toContain('https://developers.openai.com/api/docs/pricing');
  });
});
