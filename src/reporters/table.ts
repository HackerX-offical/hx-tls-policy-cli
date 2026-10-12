import chalk from 'chalk';
import type { ProtocolProbe, TlsPolicyReport } from '../types.js';

export function formatProtocolLine(p: ProtocolProbe): string {
  return `  ${p.protocol}: ${p.supported ? chalk.green(p.cipher ?? 'ok') : chalk.dim('no')}`;
}

export function formatReportHeader(report: TlsPolicyReport): string {
  return chalk.bold(`${report.host}:${report.port}`);
}
