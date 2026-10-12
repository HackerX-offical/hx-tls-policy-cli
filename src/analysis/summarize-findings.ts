import type { TlsPolicyReport } from '../types.js';

export function hasHighTlsFindings(findings: TlsPolicyReport['findings']): boolean {
  return findings.some((f) => f.severity === 'high');
}
