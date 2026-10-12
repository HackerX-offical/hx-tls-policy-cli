#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { auditTlsPolicy } from './policy.js';

const program = new Command();
program.name('hx-tls').description('TLS policy & chain audit engine').version('1.0.0');

program
  .command('audit')
  .argument('<host>')
  .option('-p, --port <n>', 'port', '443')
  .option('--json', 'JSON report')
  .action(async (host: string, opts: { port: string; json?: boolean }) => {
    const r = await auditTlsPolicy(host, Number(opts.port));
    if (opts.json) console.log(JSON.stringify(r, null, 2));
    else {
      console.log(chalk.bold(`${r.host}:${r.port}`));
      for (const p of r.protocols) {
        console.log(
          `  ${p.protocol}: ${p.supported ? chalk.green(p.cipher ?? 'ok') : chalk.dim('no')}`,
        );
      }
      for (const f of r.findings) console.log(chalk.yellow(`[${f.severity}] ${f.message}`));
    }
    process.exit(r.findings.some((f) => f.severity === 'high') ? 2 : 0);
  });

program.parse();
