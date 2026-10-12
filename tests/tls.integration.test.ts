import { auditTlsPolicy } from '../src/policy.js';

describe('auditTlsPolicy', () => {
  it('audits example.com', async () => {
    const r = await auditTlsPolicy('example.com');
    expect(r.protocols.some((p) => p.supported)).toBe(true);
    expect(r.chain.length).toBeGreaterThan(0);
  });
});
