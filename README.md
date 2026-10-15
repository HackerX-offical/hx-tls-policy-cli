# hx-tls-policy-cli

**Deep TLS policy audit** — protocol version negotiation, cipher suites, and certificate
chain review for authorized targets.

## Why this exists

Shallow `openssl s_client` one-liners miss downgrade paths and weak ciphers still
accepted on legacy VIPs. This CLI probes supported protocols, inspects the presented
chain, and emits ranked findings suitable for hardening reports and CI smoke checks.

## Features

- `audit` against host:port (default 443)
- Per-protocol handshake probes (TLS 1.0–1.3 where supported)
- Certificate chain fetch and validity findings
- Table or `--json` output; exit `2` on high-severity issues

## Install

```bash
git clone https://github.com/HackerX-official/hx-tls-policy-cli.git
cd hx-tls-policy-cli
npm install
npm run build
npm link   # optional: global hx-tls
```

## Quick start

```bash
hx-tls audit api.example.com
hx-tls audit legacy.example.com -p 8443 --json
```

## Output

| Mode     | Description                                                       |
| -------- | ----------------------------------------------------------------- |
| Default  | Header, per-protocol lines, colored finding list                  |
| `--json` | `TlsPolicyReport` with `protocols[]`, `findings[]`, cert metadata |
| Exit `2` | High-severity TLS policy issue detected                           |

## Develop

```bash
npm run format
npm run build
npm test
npm run test:integration   # optional live TLS endpoints
npm run format:check
```

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for module layout and extension points.

## Ethics

Use only on systems and content you are **authorized** to test. See
[SECURITY.md](./SECURITY.md).

## License

Licensed under the [HackerX License](./LICENSE). Redistributions must retain copyright,
license text, and [NOTICE](./NOTICE) attribution per the license terms.
