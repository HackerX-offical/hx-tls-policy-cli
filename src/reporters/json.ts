import type { TlsPolicyReport } from '../types.js';

export function reportToJson(report: TlsPolicyReport): string {
  return JSON.stringify(report, null, 2);
}
