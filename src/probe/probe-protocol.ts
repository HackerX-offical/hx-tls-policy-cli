import tls from 'node:tls';
import type { ProtocolProbe } from '../types.js';

export function probeProtocol(
  host: string,
  port: number,
  minVersion: string,
  maxVersion: string,
): Promise<ProtocolProbe> {
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
