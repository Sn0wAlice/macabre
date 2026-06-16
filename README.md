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
macabre                      # colored terminal report (baseline security)
macabre --paranoia           # deep scan: + privacy/anti-telemetry + inventory
macabre -v                   # verbose: rationale + remediation + refs
macabre --list               # list every check (id, category, profile)
macabre --only privacy,firewall   # run only these categories/ids
macabre --skip sharing            # run everything except these
macabre -f json              # machine-readable, for monitoring/diffing
macabre -f md  -o report.md  # Markdown to a file
macabre -f html -o report.html
macabre --strict             # exit non-zero if any *security* check FAILs (CI)
sudo macabre --paranoia      # some checks need root for full coverage
```

## Profiles

- **baseline** (default): security posture — integrity, encryption, firewall,
  app security, accounts, sharing, updates.
- **paranoia** (`--paranoia`): everything in baseline **plus** privacy /
  anti-telemetry checks and a deep inventory (external listeners, third-party
  launchd jobs, configuration profiles).

## What it checks

| Category | Examples |
|---|---|
| System Integrity | SIP, system-extension inventory |
| Disk Encryption | FileVault |
| Firewall | built-in + third-party (Little Snitch/LuLu/…), stealth, block-all, auto-allow-signed |
| Application Security | Gatekeeper, XProtect version |
| Accounts & Authentication | auto-login, guest, root account, admin session, screen lock |
| Sharing & Remote Access | SSH (+ sshd_config), Screen Sharing, ARD, SMB/AFP, printer, Internet Sharing, Remote Apple Events, Content Caching |
| Network Exposure | wake-on-LAN, external listening ports |
| Persistence & Profiles | third-party launchd jobs, MDM/configuration profiles |
| Software Updates | auto-check/download, security responses, critical & OS updates |
| Privacy & Telemetry *(paranoia)* | Spotlight indexing, Siri, Apple ads, analytics, AirDrop, Secure Keyboard Entry, Safari suggestions |

## Scoring

Two independent indices, each `earned / possible × 100` weighted by severity
(`PASS` = full, `WARN` = half, `FAIL`/`SKIP`/`INFO` = none of the earned credit;
`SKIP`/`INFO` aren't counted in *possible* either):

- **Security index** — always shown. Real exposure.
- **Privacy index** — shown in `--paranoia`. Anti-telemetry tradeoffs are scored
  here so a normal Mac isn't penalised on *security* for keeping Spotlight on.

All remediations are **shown, never executed**; opinionated ones (e.g. disabling
Spotlight) carry an explicit tradeoff note.

## Architecture

- `src/checks/` — one module per category; each returns `Finding`s. Add a check
  by writing a function and registering it in the module's `run()`.
- `src/report/` — decoupled renderers (terminal, json, markdown, html).
- `src/sys.rs` — read-only command wrappers.
- `src/model.rs` — `Finding`, `Status`, `Severity`, `Category`, `Score`.

## Roadmap

- [ ] Per-check CIS benchmark references
- [ ] Root-only checks: password policy, sudo timeout (currently SKIP without sudo)
- [ ] Optional live TUI dashboard
- [ ] Baseline diffing (compare two JSON reports over time)
