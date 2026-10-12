import type { ChainCert, ProtocolProbe, TlsPolicyReport } from '../types.js';

export function buildTlsFindings(
  protocols: ProtocolProbe[],
  chain: ChainCert[],
): TlsPolicyReport['findings'] {
  const findings: TlsPolicyReport['findings'] = [];
  if (protocols.find((p) => p.protocol === 'TLSv1' && p.supported)) {
    findings.push({ severity: 'high', message: 'TLS 1.0 still enabled' });
  }
  if (protocols.find((p) => p.protocol === 'TLSv1.1' && p.supported)) {
    findings.push({ severity: 'medium', message: 'TLS 1.1 still enabled' });
  }
  const leaf = chain[0];
  if (leaf?.daysRemaining !== undefined && leaf.daysRemaining < 14) {
    findings.push({
      severity: 'high',
      message: `Certificate expires in ${leaf.daysRemaining} days`,
    });
  }
  return findings;
}
