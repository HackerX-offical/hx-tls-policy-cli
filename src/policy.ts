import tls from 'node:tls';

const PROTOCOLS = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'] as const;

export interface ProtocolProbe {
  protocol: string;
  supported: boolean;
  cipher?: string;
  error?: string;
}

export interface ChainCert {
  subject?: string;
  issuer?: string;
  validTo?: string;
  daysRemaining?: number;
}

export interface TlsPolicyReport {
  host: string;
  port: number;
  protocols: ProtocolProbe[];
  chain: ChainCert[];
  findings: Array<{ severity: string; message: string }>;
}

function probeProtocol(host: string, port: number, minVersion: string, maxVersion: string): Promise<ProtocolProbe> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        minVersion: minVersion as tls.SecureVersion,
        maxVersion: maxVersion as tls.SecureVersion,
      },
      () => {
        const c = socket.getCipher();
        socket.end();
        resolve({ protocol: minVersion, supported: true, cipher: c?.name });
      },
    );
    socket.setTimeout(8000, () => {
      socket.destroy();
      resolve({ protocol: minVersion, supported: false, error: 'timeout' });
    });
    socket.on('error', (e) => {
      resolve({ protocol: minVersion, supported: false, error: e.message });
    });
  });
}

export async function auditTlsPolicy(host: string, port = 443): Promise<TlsPolicyReport> {
  const protocols: ProtocolProbe[] = [];
  for (const p of PROTOCOLS) {
    protocols.push(await probeProtocol(host, port, p, p));
  }

  const chain: ChainCert[] = await new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const raw = socket.getPeerCertificate(true);
      const certs: ChainCert[] = [];
      let c: tls.PeerCertificate | null = raw;
      const seen = new Set<string>();
      while (c && !seen.has(c.fingerprint)) {
        seen.add(c.fingerprint);
        const days = c.valid_to
          ? Math.floor((new Date(c.valid_to).getTime() - Date.now()) / 86400000)
          : undefined;
        const subj = c.subject?.CN;
        const iss = c.issuer?.CN;
        certs.push({
          subject: Array.isArray(subj) ? subj[0] : subj,
          issuer: Array.isArray(iss) ? iss[0] : iss,
          validTo: c.valid_to,
          daysRemaining: days,
        });
        c = (c as tls.PeerCertificate & { issuerCertificate?: tls.PeerCertificate }).issuerCertificate ?? null;
        if (c && c.fingerprint === raw.fingerprint) break;
      }
      socket.end();
      resolve(certs);
    });
    socket.on('error', () => resolve([]));
  });

  const findings: TlsPolicyReport['findings'] = [];
  if (protocols.find((p) => p.protocol === 'TLSv1' && p.supported)) {
    findings.push({ severity: 'high', message: 'TLS 1.0 still enabled' });
  }
  if (protocols.find((p) => p.protocol === 'TLSv1.1' && p.supported)) {
    findings.push({ severity: 'medium', message: 'TLS 1.1 still enabled' });
  }
  const leaf = chain[0];
  if (leaf?.daysRemaining !== undefined && leaf.daysRemaining < 14) {
    findings.push({ severity: 'high', message: `Certificate expires in ${leaf.daysRemaining} days` });
  }

  return { host, port, protocols, chain, findings };
}
