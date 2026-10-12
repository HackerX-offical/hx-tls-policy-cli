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
