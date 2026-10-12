import { hasHighTlsFindings } from './summarize-findings.js';

describe('hasHighTlsFindings', () => {
  it('detects high', () => {
    expect(hasHighTlsFindings([{ severity: 'high', message: 'm' }])).toBe(true);
  });
});
