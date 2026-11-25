# seleniumbase-rs-plugin-owasp

Defensive, strictly passive OWASP security auditing and [OWASP Pentest-Kit (PTK)](https://github.com/DenisPodgurskii/pentestkit) integration plugin for `seleniumbase-rs`.

## Scope & Safety Guarantees

This crate performs **100% passive posture inspection and reporting**:
- **No exploit payload generation**, fuzzing, SQLi/XSS/RCE/SSRF probes, or brute-forcing.
- **No traffic blocking or mutation** (`network()` registers passive `observe` filters only; `on_request` is not implemented).
- **Sensitive token redaction** via `redact_secret` so raw session cookies, JWT signatures, and exposed key strings are masked in findings and SARIF exports.

## Capabilities & Auditors

- **PTK Integration (`ptk`)**:
  - `PtkExtensionConfig`: validates unpacked Manifest V3 extensions (including `chromium-unpacked` artifact layouts and `dev.local.json`), validates `.crx`/`.zip` archives, parses PTK `modules.json` passive rules (`PtkModuleCatalog`), and wires unpacked extensions into `LaunchSettings::extensions` during `Plugin::before_launch`.
  - Bidirectional PTK passive reporting (`PtkScanResult`, `PtkEngine`, `effective_severity`, `owasp`, `cwe`, `wstg`, `evidence`, `remediation`) plus passive `window.PTK_AGENT` snapshot parsing (`PtkAgentSnapshot`).
- **Passive Auditors (`auditors`)**:
  - `headers`: `Strict-Transport-Security`, `Content-Security-Policy` AST (`CspPolicy`), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/COEP/CORP, server banner leaks, and CORS posture checks.
  - `cookies`: `HttpOnly`, `Secure`, `SameSite`, `__Host-`/`__Secure-` prefix rules, over-broad `Domain`, `document.cookie` session exposure, and `[redacted]` awareness when `net.sensitive` is withheld.
  - `jwt`: passive Base64URL header/claims decoder checking `alg: none`, `jku`/`x5u` headers, missing/excessive `exp`, and unencrypted PII/credential claims.
  - `dom`: passive mixed `http://` content checks, missing third-party SRI `integrity`, `target="_blank"` missing `rel="noopener noreferrer"`, Web Storage & HTML comment secret/JWT exposure, and `postMessage('*')` / DOM sink inventory.
  - `sca`: passive client-side library & version detection (`jQuery`, `Angular`, `React`, `Lodash`, `Bootstrap`, `Vue`) with offline EOL/outdated advisory lookup.
- **Reporting (`report`)**:
  - `OwaspAuditReport` with severity totals, OWASP Top 10:2021 (`A01`–`A10`) breakdown, WSTG v4.2 references, Markdown summary, PTK JSON, and SARIF v2.1.0 JSON export.

## Verification

```bash
cargo test --offline -p seleniumbase-rs-plugin-owasp
cargo test --offline -p seleniumbase-rs-plugin-owasp --no-default-features --lib --tests
cargo clippy --offline -p seleniumbase-rs-plugin-owasp --all-targets -- -D warnings
```
