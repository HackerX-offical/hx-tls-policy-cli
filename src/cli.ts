#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { auditTlsPolicy } from './policy.js';
import { reportToJson } from './reporters/json.js';
import { hasHighTlsFindings } from './analysis/summarize-findings.js';
import { formatProtocolLine, formatReportHeader } from './reporters/table.js';

const program = new Command();
program.name('hx-tls').description('TLS policy & chain audit engine').version('1.0.0');

program
  .command('audit')
  .argument('<host>')
  .option('-p, --port <n>', 'port', '443')
  .option('--json', 'JSON report')
  .action(async (host: string, opts: { port: string; json?: boolean }) => {
    const r = await auditTlsPolicy(host, Number(opts.port));
    if (opts.json) console.log(reportToJson(r));
    else {
      console.log(formatReportHeader(r));
      for (const p of r.protocols) console.log(formatProtocolLine(p));
      for (const f of r.findings) console.log(chalk.yellow(`[${f.severity}] ${f.message}`));
    }
    process.exit(hasHighTlsFindings(r.findings) ? 2 : 0);
  });

program.parse();
