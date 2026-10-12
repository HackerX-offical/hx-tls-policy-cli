import { TLS_PROTOCOLS } from './protocols.js';

describe('TLS_PROTOCOLS', () => {
  it('includes 1.3', () => {
    expect(TLS_PROTOCOLS).toContain('TLSv1.3');
  });
});
