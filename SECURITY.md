# Security Policy

This document covers the **open‑core scanner** (MIT). The proprietary Intelligence Layer (`agent/`) performs post‑processing only; vulnerabilities confined exclusively to proprietary enrichment logic follow a separate private response process and are out of public scope unless they materially impact core output integrity.

## Supported Versions

| Track | Scope | Supported |
|-------|-------|-----------|
| `main` (0.1.x dev) | Core scanner | ✅ Security & correctness fixes (rolling)
| Pre‑0.1.0 historical commits | Core scanner | Best effort (upgrade recommended)
| Proprietary Intelligence Layer | Enrichment | Private channel (commercial / evaluation agreements)

Until a 1.0.0 semantic milestone the project maintains a single rolling support line on `main` for the core.

## Reporting a Vulnerability (Core)

Please **do not open a public issue** for potential security problems.

Preferred channel (core):
1. GitHub Security Advisory draft: https://github.com/J-mazz/sys-scan/security/advisories/new

Fallback: email joseph@mazzlabs.works with: affected commit/version, reproduction steps, impact, suggested remediation.

Proprietary layer issues: use the private commercial support channel specified in your agreement (or the same email referencing your license). Disclose only the minimal technical detail needed for triage if uncertain which layer is impacted.

## What to Expect

| Phase | Target Response Time |
|-------|----------------------|
| Initial acknowledgement | 3 business days |
| Triage & severity classification | 7 days |
| Fix development (typical) | 14 days |
| Coordinated disclosure (if high/critical) | Mutually agreed |

If you do not receive a response within the acknowledgment window, feel free to gently follow up or (as a last resort) open a minimal issue referencing that you attempted private contact (without disclosing details).

## Scope (Public Core)

In Scope:
* Logic / parsing errors enabling privilege escalation, info leak, denial of service, or code execution within the scanning process
* Unsafe temp file usage or race conditions (TOCTOU) in scanners
* Path traversal / symlink attacks within collection code paths
* Integrity compromise of canonical JSON output (spoofed provenance, ordering manipulation, injection of unbounded user-controlled data)

Out of Scope (Core) unless chainable to impact:
* Pure cosmetic output formatting issues
* Heuristic false positives / false negatives (file a regular issue)
* Performance optimizations absent explicit resource exhaustion
* Vulnerabilities strictly within proprietary enrichment (handled privately)

## Handling & Disclosure

- High / critical issues may receive a coordinated disclosure date; low risk issues are typically patched and released immediately.
- Credit will be given in release notes unless you request anonymity.
- We may backport critical fixes if/when multiple maintained release lines exist.

## Hardening Roadmap (Core)
* Expand seccomp profile granularity & tighten allowed syscalls per phase
* Landlock / user namespace isolation exploration (optional flag)
* Broader file integrity verification (package db cross‑checks)
* Additional fuzz harnesses (scanner parsers & rule engine) beyond existing rules fuzzer
* Continuous static analysis (clang‑tidy gating, CodeQL queries expansion)

## Responsible Use

The scanner enumerates sensitive host configuration & runtime data. Operate only on systems you are explicitly authorized to assess. Downstream enrichment MUST preserve confidentiality constraints present at collection time.

---
If you have suggestions to improve this policy, open a regular issue (non-sensitive) or include them in an advisory thread.
