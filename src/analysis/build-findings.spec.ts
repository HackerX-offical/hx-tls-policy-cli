import { buildTlsFindings } from './build-findings.js';

describe('buildTlsFindings', () => {
  it('flags TLS1', () => {
    const f = buildTlsFindings([{ protocol: 'TLSv1', supported: true }], []);
    expect(f.some((x) => x.message.includes('TLS 1.0'))).toBe(true);
  });
});
