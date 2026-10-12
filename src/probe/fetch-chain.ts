import tls from 'node:tls';
import type { ChainCert } from '../types.js';

export function fetchCertificateChain(host: string, port: number): Promise<ChainCert[]> {
  return new Promise((resolve) => {
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
        c =
          (c as tls.PeerCertificate & { issuerCertificate?: tls.PeerCertificate })
            .issuerCertificate ?? null;
        if (c && c.fingerprint === raw.fingerprint) break;
      }
      socket.end();
      resolve(certs);
    });
    socket.on('error', () => resolve([]));
  });
}
