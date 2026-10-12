import { reportToJson } from './json.js';

describe('reportToJson', () => {
  it('serializes', () => {
    expect(
      JSON.parse(reportToJson({ host: 'h', port: 443, protocols: [], chain: [], findings: [] }))
        .host,
    ).toBe('h');
  });
});
