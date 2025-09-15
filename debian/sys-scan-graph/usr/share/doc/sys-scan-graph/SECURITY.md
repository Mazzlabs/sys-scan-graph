# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (0.1.x dev) | ✅ Security fixes
| Pre-release commits before initial tag | ✅ (best effort)
| Future tagged releases (>=1.0) | (Will list once tagged)

> Until a 1.0.0 release, the project follows a rolling security support model: the `main` branch is the only supported line.

## Reporting a Vulnerability

Please **do not open a public GitHub Issue for security problems**.

Use one of these private channels instead:

1. **GitHub Security Advisory (preferred)**  
   Open a draft advisory here: https://github.com/Mazzlabs/sys-scan-graph/security/advisories/new  
   This creates a private workspace where we can discuss details and coordinate a fix & disclosure timeline.

2. **Email (fallback)**  
   If you cannot use advisories, email: joseph@mazzlabs.works  
   Please include: affected version / commit, environment, reproduction steps, impact assessment, and any suggested fixes.

## What to Expect

| Phase | Target Response Time |
|-------|----------------------|
| Initial acknowledgement | 3 business days |
| Triage & severity classification | 7 days |
| Fix development (typical) | 14 days |
| Coordinated disclosure (if high/critical) | Mutually agreed |

If you do not receive a response within the acknowledgment window, feel free to gently follow up or (as a last resort) open a minimal issue referencing that you attempted private contact (without disclosing details).

## Scope

In scope:
- Logic / parsing errors leading to privilege escalation, info leak, DoS, or code execution
- Unsafe temporary file usage
- Path traversal or symlink race issues in scanners
- Insecure handling of world-writable / user-influenced data

Out of scope (unless clearly exploitable):
- Cosmetic output issues
- Performance inefficiencies
- False positives / false negatives in heuristic scanners (submit as normal issues)

## Handling & Disclosure

- High / critical issues may receive a coordinated disclosure date; low risk issues are typically patched and released immediately.
- Credit will be given in release notes unless you request anonymity.
- We may backport critical fixes if/when multiple maintained release lines exist.

## Hardening Roadmap (Security Related)
- Add sandboxing (seccomp / pledge-like restrictions) for network & IOC scanning phases
- Introduce optional file hashing & integrity verification
- Add comprehensive input bounds checks and fuzz harnesses (libFuzzer/AFL++)
- Continuous static analysis (clang-tidy, CodeQL)

## Responsible Use

This tool enumerates sensitive system metadata. Use only on systems you are authorized to assess.

---
If you have suggestions to improve this policy, open a regular issue (non-sensitive) or include them in an advisory thread.
