# sys-scan

![CI](https://github.com/J-mazz/sys-scan/actions/workflows/ci.yml/badge.svg) ![License: Core MIT / Intelligence Proprietary](https://img.shields.io/badge/License-Open--core%20Hybrid-blue.svg)

Professional host security & hygiene assessment built on a lean, deterministic C++20 scanning engine. The open‑core scanner delivers trustworthy, reproducible telemetry; an optional proprietary Intelligence Layer (this fork) transforms that raw signal into correlated insights, baselines, rarity analytics, compliance gap normalization, ATT&CK coverage summaries, and executive reporting.

This codebase intentionally enforces a **clean boundary**:
* `src/`, `rules/`, `schema/`  – Open‑core scanner (MIT). Upstream reference: https://github.com/J-mazz/sys-scan
* `agent/` – Proprietary Intelligence Layer (evaluation / commercial license). Not required for basic scanning. All enrichment happens post‑collection from stable JSON interfaces.

Why this design:
* Predictable, attestable core artifact (deterministic canonical JSON & reproducible build knobs)
* Safe consumption in regulated pipelines (no outbound network activity by default)
* Pluggable enrichment surface (rules, schemas, post‑processors) enabling differentiated value without forking core logic

Key value propositions:
* High‑signal grouped findings (noise compression at collection time)
* Deterministic canonical output → hash, sign, attest, diff reliably
* Extensible rule engine & compliance scaffolding
* Optional advanced analytics (rarity, correlation, HTML & diff reports) without bloating the core binary
* Explicit security hardening (cap drop, seccomp, provenance metadata)

---
## Table of Contents
1. Quick Start
2. Intelligence Layer Overview
3. Core Feature Highlights
4. Scanner Inventory
5. Output Contracts (JSON / NDJSON / SARIF)
6. Rules & Open Interfaces
7. Determinism & Provenance
8. Security & Hardening
9. Risk & Severity Model
10. Schema & Versioning
11. Build & Install
12. Usage Recipes
13. CI / Pipeline Integration
14. Examples
15. Advanced Flags
16. Roadmap (Core & Intelligence)
17. Licensing Model

---
## 1. Quick Start
```bash
git clone https://github.com/J-mazz/sys-scan.git
cd sys-scan
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
./build/sys-scan --pretty --modules-summary --min-severity info > report.json
```
View compact canonical (stable hash) report:
```bash
SYS_SCAN_CANON_TIME_ZERO=1 ./build/sys-scan --canonical > canon.json
sha256sum canon.json
```

Minimal pipelines (stdout):
```bash
./build/sys-scan --ndjson | grep '"type":"finding"'
```

---
## 2. Intelligence Layer Overview
Although the scanning engine is intentionally compact, the bulk of the product value lives in the Intelligence Layer which provides advanced enrichment and reporting capabilities beyond raw collection.

### What It Does
| Capability | Purpose | Outcome |
|------------|---------|---------|
| Typed ingestion & schema validation | Parse stable core JSON into versioned Pydantic models | Forward compatibility & safety gates |
| Baselining & rarity scoring | Persist historical observation vectors (SQLite) | Surface statistically rare changes, suppress churn |
| Deterministic correlation graph | Link related low-signal findings into composite hypotheses | Higher precision, reduced alert fatigue |
| Compliance gap normalization | Map raw control signals to unified gap taxonomy | Consistent remediation meta across frameworks |
| Rule enrichment & MITRE coverage | Aggregate technique tags & fill coverage matrices | Fast ATT&CK reporting, gap views |
| Risk re-scoring & prioritization | Multi-factor weighting (rarity, severity, temporal decay) | Ordered remediation queue |
| HTML / diff / executive reports | Multi-audience formatted outputs (tech ops, exec) | Accelerated decision cycles |
| Redaction & privacy filters | Remove / hash sensitive fields pre-export | Safer sharing & ticketing |
| Counterfactual & refinement utilities | Suggest rule adjustments / redundancy pruning | Leaner rule sets over time |
| (Optional) Summarization adapters | Deterministic prompt scaffolding (LLM off by default) | Human-readable context where enabled |

### Pipeline Flow (Conceptual)
```
 Core JSON -> Loader -> Validation -> (Baseline Store ↔ Rarity Engine)
				  |                
				  v
			 Correlation Layer -> Risk Scoring -> Compliance Normalizer
				  |                                 |
				  +----------> Coverage Matrix <----+
				  |
				  v
			  Report Builders (HTML / Diff / JSON+)
				  |
			  Redaction & Export Adapters
```

### Design Tenets
* Pure consumer: never mutates core collection logic.
* Deterministic first: identical inputs + state snapshot → identical outputs (facilitates reproducible investigations).
* Extensible modules: new enrichment stages register declaratively; graph orchestration (fork) prototypes inform future DAG upgrade.
* Safe offline default: no outbound network; optional remote augmentation is additive & opt-in.

If you only need a fast, attestable scan artifact, use the core. If you need prioritized, contextual, privacy-aware security narrative, enable the Intelligence Layer.

## 3. Core Feature Highlights
* High‑signal grouping & dual metrics (total vs emitted) reduce alert fatigue.
* Deterministic canonical JSON (RFC8785 subset) + optional timestamp zeroing → stable cryptographic hashes.
* Multiple emissions: JSON, NDJSON streaming (pipeline friendly), SARIF 2.1.0.
* Declarative rule engine (multi‑condition, regex, severity override, MITRE aggregation).
* Optional compliance scanners (PCI DSS 4.0, HIPAA, NIST CSF) with summarized pass/fail & gap arrays.
* Experimental eBPF exec trace (`--ioc-exec-trace`) augments IOC heuristics (soft‑fail if unavailable).
* Built‑in hardening: capability drop, seccomp (opt), reproducible build flags, provenance embeddings.
* Strictly local collection: zero outbound network calls by default.
* Clean API surface (schemas + rules) enabling innovation in proprietary enrichment without polluting core.

---
## 4. Scanner Inventory
| Scanner | Focus | Notable Signals |
|---------|-------|-----------------|
| Process | Userland processes | Deleted executables, temp exec, env LD anomalies, executable hashing (opt) |
| Network | TCP/UDP sockets | Listening exposure, high fan‑out heuristics (planned) |
| Kernel Params | sysctl / /proc | Insecure kernel tunables (planned extensions) |
| Kernel Modules | Loaded & filesystem state | Unsigned, out‑of‑tree, missing file, hidden vs sysfs, compressed .ko scan |
| World Writable | Directories & files | Writable risk surfaces & path hijack potential |
| SUID/SGID | Privileged binaries | Unexpected SUID set, baseline expected set downgrade |
| IOC | Execution context | ld.so.preload abuse, deleted binaries, env risk aggregation |
| MAC | SELinux/AppArmor status | Missing MAC, downgrade logic if one present |
| Compliance (opt) | PCI / HIPAA / NIST CSF controls | Pass/fail aggregation + gap analysis (when enabled) |
| Integrity (opt) | Future pkg/IMA | Placeholders for package & IMA measurement stats |
| Exec Trace (opt) | eBPF execve events | Short‑lived process capture window (libbpf, optional) |
| Rules | Post-processing layer | MITRE tagging, severity escalation |

---
## 5. Output Contracts
Base JSON always contains:
* `meta` – environment + provenance.
* `summary` – dual counts, severities, timings, slowest scanner.
* `results[]` – per-scanner groups.
* `collection_warnings[]` & `scanner_errors[]` – non-fatal diagnostics.
* `summary_extension` – extended scoring (total & emitted risk).

Optional:
* `--canonical` enforces deterministic ordering & minimal whitespace (RFC8785 style stabilization).
* `--ndjson` streams: meta, summary_extension, each finding (easy piping).
* `--sarif` produces SARIF for code scanning ingestion.

---
## 6. Rules & Open Interfaces
Capabilities:
* Declarative rule files (`.rule`) with `rule_version` guard.
* AND/OR logic; equality, regex (`~=`), substring future extension.
* MITRE technique aggregation (order‑preserving de‑dup).
* Severity override & notes.
* Structured warnings on invalid/legacy versions (non‑fatal unless gated).

Example:
```
rule_version = 1

rule "Escalate deleted suspicious binary" {
	when {
Runtime overrides via env (`SYS_SCAN_PROV_*`) or `--slsa-level`. Deterministic canonical mode + optional timestamp zeroing yields stable hashes for attestations or artifact promotion.

SYS_SCAN_CANON_TIME_ZERO=1 ./b/sys-scan --canonical > r.json
sha256sum r.json
```
Generate provenance env file:
```bash
./b/sys-scan --write-env build.env --output report.json --canonical
cat build.env
```

---
## 9. Risk & Severity Model
Each finding has:
* `severity`: info, low, medium, high, critical, error
* `risk_score`: integer 0‑100 (heuristic weighting per scanner)

`summary_extension.total_risk_score` sums all scores; `emitted_risk_score` reflects active filter (`--min-severity`). This enables gating on both signal density and threshold severity simultaneously.

Filtering examples:
```bash
# Only medium+ and fail pipeline if any high+
./sys-scan --min-severity medium --fail-on high

# Gate on volume (after filtering)
./sys-scan --min-severity low --fail-on-count 150
```

---
## 10. Schema & Versioning
Current schema: `v2` (`meta.json_schema_version = "2"`). Additive fields keep same major; breaking semantic shifts bump major.

File: `schema/v2.json` – validated via tests. Dual metrics & emitted risk score are enumerated. Additional properties intentionally permitted for forward flexibility (attestation/deployment contexts).

---
## 11. Build & Install
### Standard Build
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
./build/sys-scan --version
```

### Options (CMake)
| Option | Default | Effect |
|--------|---------|--------|
| `BUILD_TESTS` | ON | Build test binaries & enable ctest targets |
| `ENABLE_OPENSSL` | ON | Use OpenSSL for hashing (graceful fallback) |
| `ENABLE_SECCOMP` | ON | Discover & enable seccomp support |
| `ENABLE_CAPABILITIES` | ON | Enable capability dropping |
| `SYS_SCAN_REPRO_BUILD` | OFF | Repro build defines; strip volatile macros |
| `BUILD_FUZZERS` | OFF | Build libFuzzer harnesses (clang) |

### Package Artifacts
Debian packaging skeleton under `debian/` (invoke standard `dpkg-buildpackage` flow) – future refinement may add signed packages / provenance embedding.

---
## 12. Usage Recipes
| Scenario | Command |
|----------|---------|
| Quick hygiene sweep | `./sys-scan --modules-summary --min-severity medium` |
| Attestable artifact | `SYS_SCAN_CANON_TIME_ZERO=1 ./sys-scan --canonical --output rep.json` |
| Signed report | `./sys-scan --canonical --output rep.json --sign-gpg <KEY>` |
| Stream to SIEM | `./sys-scan --ndjson | jq -c 'select(.type=="finding")'` |
| Rule enrichment | `./sys-scan --rules-enable --rules-dir rules/` |
| Tight CI gate | `./sys-scan --min-severity low --fail-on high --fail-on-count 250` |
| Max transparency | `./sys-scan --process-inventory --modules-summary --process-hash` |

---
## 13. CI / Pipeline Integration
Suggested stages:
3. Optional signing (`--sign-gpg`).
4. Policy gate: severity & count thresholds.
5. Upload artifacts (report.json + report.json.asc + build.env).

	echo "Gate failed" >&2; exit 1; }
```

Streaming to SARIF‑aware platforms:
```bash
./sys-scan --sarif > results.sarif
```
---
## 14. Examples
### Canonical JSON (excerpt)
```json
{
	"meta":{"hostname":"host","tool_version":"0.1.0","json_schema_version":"2"},

### NDJSON (first lines)
```json
{"type":"meta","tool_version":"0.1.0","schema":"2"}
{"type":"summary_extension","total_risk_score":880,"emitted_risk_score":310}
{"type":"finding","scanner":"process","id":"1234",...}
```

### SARIF (excerpt)
```json
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"sys-scan"}},"results":[{"ruleId":"proc_deleted","level":"high",...}]}]}
```

---
## 15. Advanced Flags Reference
```
--enable name[,name...]       Only run specified scanners
--disable name[,name...]      Disable specified scanners
--output FILE                 Write JSON to FILE (default stdout)
--min-severity SEV            Filter out findings below SEV
--fail-on SEV                 Exit non-zero if any finding >= SEV
--pretty                      Pretty-print JSON
--compact                     Force minimal JSON (overrides pretty)
--all-processes               Include kernel/thread processes lacking cmdline
--world-writable-dirs dirs    Extra comma-separated directories to scan
--world-writable-exclude pats Comma-separated substrings to ignore
--max-processes N             Cap process findings after filtering
--max-sockets N               Cap network socket findings
--network-debug               Include raw /proc/net lines in findings
--network-listen-only         Limit to listening TCP (and bound UDP) sockets
--network-proto tcp|udp       Protocol filter
--network-states list         Comma-separated TCP states (LISTEN,ESTABLISHED,...)
--ioc-allow list              Comma-separated substrings to downgrade env IOC
--modules-summary             Collapse module list into single summary finding
--modules-anomalies-only      Only emit unsigned/out-of-tree module entries (no summary)
--modules-hash                Include SHA256 of module file (if OpenSSL available)
--process-hash                Include SHA256 hash of process executable (first 1MB) if OpenSSL available
--process-inventory           Emit all processes (otherwise only IOC/anomalies)
--ioc-allow-file FILE         Newline-delimited additional env allowlist patterns
--fail-on-count N             Exit non-zero if total finding count >= N
--suid-expected list          Extra expected SUID paths (comma list)
--suid-expected-file FILE     Newline-delimited expected SUID paths
--canonical                   Emit canonical JSON (stable ordering & formatting)
--ndjson                      Emit newline-delimited meta/summary/finding lines
--sarif                       Emit SARIF 2.1.0 run
--rules-enable                Enable rule enrichment engine
--rules-dir DIR               Directory containing .rule files
--rules-allow-legacy          Allow loading legacy rule_version without hard fail
--no-user-meta                Suppress user/uid/gid/euid/egid in meta
--no-cmdline-meta             Suppress cmdline in meta
--no-hostname-meta            Suppress hostname in meta
--drop-priv                   Drop Linux capabilities early (best-effort; requires libcap)
--keep-cap-dac                Retain CAP_DAC_READ_SEARCH when using --drop-priv
--seccomp                     Apply restrictive seccomp-bpf profile after initialization
--seccomp-strict              Treat seccomp apply failure as fatal (exit code 4)
--sign-gpg KEYID              Detached ASCII armored signature (requires --output)
--write-env FILE              Emit .env file with version & binary hash
--slsa-level N                Declare SLSA build level (meta.provenance)
--version                     Print version & provenance summary
--help                        Show usage
```

> Placeholder for future screenshot: (Report summary terminal capture)
> Placeholder for future screenshot: (SARIF ingestion view)

---
## 16. Roadmap (Core & Intelligence)
Core (MIT): performance refinements, additional scanners (package integrity, process ancestry anomalies), finer-grained seccomp profile, structured warning channel, parallel scanner execution.

Intelligence (Proprietary): DAG orchestration promotion (graph mode), probabilistic risk calibration, richer counterfactual explanations, temporal drift clustering, multi-host fleet aggregation, adaptive suppression suggestions, signed enriched artifact chain.
See also inline comments / issues. Near‑term concepts:
* Extended risk scoring calibrations.
* Package integrity (dpkg/rpm verify) & mismatch aggregation.
* Landlock / chroot sandbox addition.
* eBPF exec short‑lived process tracing (`--ioc-exec-trace`).
* Enhanced network exposure heuristics & fan‑out thresholds.
* Additional output signing backends (cosign, age).

## 17. Licensing Model
Open‑core hybrid:
* Core scanner (everything required to build and run `sys-scan` under `src/`, plus `rules/`, `schema/`) – MIT License (SPDX: MIT). Upstream canonical repository: https://github.com/J-mazz/sys-scan
* Intelligence Layer (`agent/` and its Python dependencies, enrichment logic, HTML & diff reporting) – Proprietary. Evaluation / commercial terms govern redistribution & derivative works of this directory.

Separation Principles:
* Build of the core binary never links or imports proprietary code.
* Proprietary layer only reads JSON / NDJSON / SARIF produced by the MIT core.
* Removal of `agent/` yields a clean MIT codebase with unchanged deterministic hashes.

Contribution Scope: External contributions are welcomed for the MIT core (performance, new scanners, rule engine improvements). Proprietary enrichment roadmap is managed privately.

See `LICENSE` for the MIT notice and proprietary notice headers.


## CLI Overview
```
--enable name[,name...]       Only run specified scanners
--disable name[,name...]      Disable specified scanners
--output FILE                 Write JSON to FILE (default stdout)
--min-severity SEV            Filter out findings below SEV
--fail-on SEV                 Exit non-zero if any finding >= SEV
--pretty                      Pretty-print JSON
--compact                     Force minimal JSON (overrides pretty)
--all-processes               Include kernel/thread processes lacking cmdline
--world-writable-dirs dirs    Extra comma-separated directories to scan
--world-writable-exclude pats Comma-separated substrings to ignore
--max-processes N             Cap process findings after filtering
--max-sockets N               Cap network socket findings
--network-debug               Include raw /proc/net lines in findings
--network-listen-only         Limit to listening TCP (and bound UDP) sockets
--network-proto tcp|udp       Protocol filter
--network-states list         Comma-separated TCP states (LISTEN,ESTABLISHED,...)
--ioc-allow list              Comma-separated substrings to downgrade env IOC
--modules-summary             Collapse module list into single summary finding
--modules-anomalies-only      Only emit unsigned/out-of-tree module entries (no summary)
--process-hash                Include SHA256 hash of process executable (first 1MB) if OpenSSL available
--process-inventory           Emit all processes (otherwise only IOC/anomalies)
--ioc-allow-file FILE         Newline-delimited additional env allowlist patterns
--fail-on-count N             Exit non-zero if total finding count >= N
--suid-expected list          Extra expected SUID paths (comma list)
--suid-expected-file FILE     Newline-delimited expected SUID paths
--canonical                   Emit RFC8785 canonical JSON (stable ordering & formatting)
--ndjson                      Emit newline-delimited meta/summary/finding lines (stream friendly)
--sarif                       Emit SARIF 2.1.0 run with findings as results
--rules-enable                Enable rule enrichment engine
--rules-dir DIR               Directory containing .rule files
--rules-allow-legacy          Allow loading legacy rule_version without hard fail
--no-user-meta                Suppress user/uid/gid/euid/egid in meta
--no-cmdline-meta             Suppress cmdline in meta
--no-hostname-meta            Suppress hostname in meta
--drop-priv                   Drop Linux capabilities early (best-effort; requires libcap)
--keep-cap-dac                Retain CAP_DAC_READ_SEARCH when using --drop-priv
--seccomp                     Apply restrictive seccomp-bpf profile after initialization (libseccomp)
* `--seccomp` – installs a minimal allowlist seccomp-bpf program early, before scanning.
* `--seccomp-strict` – treat failure to apply seccomp as fatal (exit code 4).
--sign-gpg KEYID              Detached ASCII armored signature (requires --output)
--write-env FILE              Emit .env file with version, git commit (if available), binary SHA256
--slsa-level N                Declare SLSA build level (meta.provenance)
--help                        Show usage
```

## Build (Debian/Ubuntu)
```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
./build/sys-scan --help
```

## Testing
```
cd build
ctest --output-on-failure
```
Key tests:
* `canonical_golden` – regression guard for canonical stable hash
* `ndjson_mitre` – MITRE technique formatting in NDJSON
* `rules_*` – rule engine multi-condition, version, warnings, MITRE de‑dup
* `meta_suppression` – metadata privacy flags honor suppression
* `canonical_golden` – also guards provenance field stability (hash updates only on intentional schema or provenance additions)

## Result Integrity & Provenance

Canonical JSON (`--canonical`) plus deterministic ordering (& optional `SYS_SCAN_CANON_TIME_ZERO=1`) enables stable hashing of reports. To attest integrity you can:
Provenance override environment variables (if set, override embedded build constants): `SYS_SCAN_PROV_GIT_COMMIT`, `SYS_SCAN_PROV_COMPILER_ID`, `SYS_SCAN_PROV_COMPILER_VERSION`, `SYS_SCAN_PROV_CXX_STANDARD`, `SYS_SCAN_PROV_CXX_FLAGS`, `SYS_SCAN_PROV_SLSA_LEVEL`, `SYS_SCAN_PROV_BUILD_TYPE`.

1. Produce report: `./sys-scan --canonical --output report.json`
2. (Optional) Zero timestamps for fully reproducible hash: `SYS_SCAN_CANON_TIME_ZERO=1 ./sys-scan --canonical --output report.json`
3. Sign with GPG: `./sys-scan --canonical --output report.json --sign-gpg <KEYID>` (emits `report.json.asc` detached signature)

The `meta.provenance` object embeds build metadata for supply‑chain transparency:
```
"provenance": {
	"git_commit": "<short-hash>",
	"compiler_id": "GNU|Clang|...",
	"compiler_version": "<ver>",
	"cxx_standard": "20",
	"cxx_flags": "<merged flags>",
	"slsa_level": "<declared level>",
	"build_type": "Release|Debug"
}
```
Runtime override: `--slsa-level` (or env `SYS_SCAN_SLSA_LEVEL_RUNTIME`) if you want to declare an attested SLSA build level at execution time.

### Reproducible Builds

The project avoids embedding volatile timestamps (unless you rely on external libraries that do so). For stricter reproducibility:

Recommended invocation:
```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
	-DSYS_SCAN_REPRO_BUILD=ON -DSYS_SCAN_SLSA_LEVEL=1 \
	-DCMAKE_CXX_FLAGS_RELEASE="-O2 -g0 -ffile-prefix-map=$(pwd)=. -fdebug-prefix-map=$(pwd)=."
cmake --build build -j$(nproc)
SOURCE_DATE_EPOCH=1700000000 SYS_SCAN_CANON_TIME_ZERO=1 ./build/sys-scan --canonical --output report.json
sha256sum report.json
```
Notes:
* `SYS_SCAN_REPRO_BUILD=ON` scrubs `__DATE__/__TIME__` and marks build reproducible.
* `SYS_SCAN_CANON_TIME_ZERO=1` normalizes all timestamps to epoch and sets `meta.normalized_time=true`.
* Use toolchain packaged compilers for determinism; ensure locale + TZ stable (e.g. `LC_ALL=C TZ=UTC`).
* Provide `--sign-gpg` to generate a detached signature after writing the file.

Future options may add cosign / age signing modes; current implementation focuses on ubiquitous GPG.

### Schema

The JSON Schema (`schema/v2.json`) explicitly enumerates dual metrics: `finding_count_total` vs `finding_count_emitted`, `severity_counts` vs `severity_counts_emitted`, and includes `emitted_risk_score` in `summary_extension` alongside `total_risk_score`. Additional properties remain open for forward compatibility; provenance and normalization flags (`meta.provenance`, `meta.normalized_time`) are permitted via `additionalProperties`.
## Roadmap Ideas
- Add hashing of binaries (optional OpenSSL/Blake3)
- Add package integrity checks (dpkg --verify)
 - Extract canonical IR structs (CanonVal) into shared header for potential external tooling
 - Additional SARIF properties (locations, partial fingerprints)

## Operational Tips
- Use `--modules-summary` to shrink report size in continuous runs.
- Combine `--min-severity medium` with `--fail-on high` in CI to gate only on stronger signals.
- Add benign path substrings to `--ioc-allow` (e.g. `/snap/,/flatpak/`) to reduce env IOC noise further.

## Roadmap (Short-Term)
Taint flags, numeric risk scoring, allowlist file (`--ioc-allow-file`), package integrity & systemd hardening checks, advanced MAC profiling.

## License
Licensed under the MIT License. See `LICENSE` for full text.

---
### Phase 10 Productization Demo
A quick end-to-end demonstration (two scans, enrichment, HTML generation, diff, manifest, timing):
```bash
./scripts/demo_phase10.sh
```
Outputs:
- report_demo_1.json / report_demo_2.json (raw C++ scanner outputs)
- enriched_demo_1.json / enriched_demo_2.json (Python agent enriched)
- enriched_report.html (static dashboard)
- enriched_diff.md (risk movement & new/removed findings)
- manifest.json (version, rule pack SHA, embedding model hash, weights)

The script prints total wall time for two enrichment runs; single-run latency should target <1.5s on a modern laptop for typical host sizes.
