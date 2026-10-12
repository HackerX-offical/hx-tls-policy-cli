import type { TlsPolicyReport } from '../types.js';
import { TLS_PROTOCOLS } from '../constants/protocols.js';
import { probeProtocol } from '../probe/probe-protocol.js';
import { fetchCertificateChain } from '../probe/fetch-chain.js';
import { buildTlsFindings } from '../analysis/build-findings.js';

export async function auditTlsPolicy(host: string, port = 443): Promise<TlsPolicyReport> {
  const protocols = [];
  for (const p of TLS_PROTOCOLS) {
    protocols.push(await probeProtocol(host, port, p, p));
  }
  const chain = await fetchCertificateChain(host, port);
  const findings = buildTlsFindings(protocols, chain);
  return { host, port, protocols, chain, findings };
}
