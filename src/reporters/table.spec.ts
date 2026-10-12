import { formatProtocolLine, formatReportHeader } from './table.js';

describe('table reporter', () => {
  it('formats header', () => {
    expect(formatReportHeader({ host: 'h', port: 443, protocols: [], chain: [], findings: [] })).toContain('h:443');
  });
  it('formats protocol', () => {
    expect(formatProtocolLine({ protocol: 'TLSv1.3', supported: true, cipher: 'x' })).toContain('TLSv1.3');
  });
});
