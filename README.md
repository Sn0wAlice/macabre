# macabre

A read-only **macOS hardening & security audit scanner**, written in Rust.

`macabre` inspects local security settings, scores the host with a weighted
*hardening index*, and reports findings to a colored terminal view (lynis-style)
or exports them as JSON / Markdown / HTML. It **only reads** system state — it
never changes anything. Failing checks include the exact command you'd run to
fix them.

## Build

```sh
cargo build --release
# binary at target/release/macabre
```

## Usage

```sh
macabre                      # colored terminal report
macabre -v                   # verbose: rationale + remediation + refs
macabre -f json              # machine-readable, for monitoring/diffing
macabre -f md  -o report.md  # Markdown to a file
macabre -f html -o report.html
macabre --strict             # exit non-zero if any check FAILs (CI)
```

## What it checks (v0.1)

| Category | Checks |
|---|---|
| System Integrity | SIP |
| Disk Encryption | FileVault |
| Firewall | Application firewall, stealth mode |
| Application Security | Gatekeeper |
| Sharing & Remote Access | SSH, Screen Sharing, ARD, SMB |
| Software Updates | auto-check, auto-download, security responses, OS updates |

## Scoring

Each scored check is weighted by severity (low → critical). The hardening index
is `earned / possible × 100`, where a `PASS` earns full weight, a `WARN` earns
half, and a `FAIL` earns none. `SKIP`/`INFO` findings don't affect the score.

## Architecture

- `src/checks/` — one module per category; each returns `Finding`s. Add a check
  by writing a function and registering it in the module's `run()`.
- `src/report/` — decoupled renderers (terminal, json, markdown, html).
- `src/sys.rs` — read-only command wrappers.
- `src/model.rs` — `Finding`, `Status`, `Severity`, `Category`, `Score`.

## Roadmap

- [ ] More checks: password policy, screensaver lock, sudo timeout, secure
      keyboard entry, automatic login, AirDrop, Bluetooth sharing, listening ports
- [ ] Per-check CIS benchmark references
- [ ] `--only`/`--skip` category filters
- [ ] Optional live TUI dashboard
