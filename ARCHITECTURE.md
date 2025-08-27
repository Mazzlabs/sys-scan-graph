# Architecture

## Overview
`sys-scan` (Core) is a single-binary Linux host inspection engine composed of pluggable *Scanner* units that populate a shared in‑memory `Report`. It produces deterministic, schema‑versioned JSON suitable for hashing, signing, attestation, diffing, or downstream enrichment. An optional proprietary Intelligence Layer (Python, under `agent/`) ingests that JSON strictly as a read‑only contract—there is no runtime coupling back into core collection routines.

```
         +---------------------------+
         |        Intelligence       |  (Proprietary Python)
         |  - Rarity & Baselines     |
 Upstream MIT    |  - Correlations           |    Consumes JSON / NDJSON / SARIF
 Core JSON  ---> |  - Compliance Gap Norm    |    (No reverse calls)
         |  - ATT&CK Coverage        |
         |  - HTML / Diff Reports    |
         +--------------^------------+
                |
            Stable JSON Contract
                |
 +-------------------------------+-----------------------------+
 |                         Core (MIT)                          |
 |  CLI -> Config -> ScannerRegistry -> Scanner Loop -> Report |
 |                                        |                    |
 |                                        v                    |
 |                                   JSONWriter --------------> stdout/file
 +-------------------------------------------------------------+
```

## Core Components (MIT)
* Scanner interface (`Scanner` in `core/Scanner.h`): name(), description(), scan(Report&).
* Registry (`ScannerRegistry`): Instantiates and runs all default scanners in sequence (single‑threaded for deterministic ordering; structure prepared for future parallelization).
* Report (`Report`): Thread-safe append-only container of `ScanResult` objects enabling safe future concurrency.
* Finding model: Plain struct with stable, deterministic field ordering (string severity & key‑sorted metadata map).
* Config (`Config`): Parsed once at startup; exposes feature flags / numeric thresholds.
* JSONWriter: Emits canonical ordering + minimal whitespace (canonical mode) and annotates version/provenance. Optional pretty printing kept logically separate so canonical output's hash is stable.

## Scanner Flow
1. `ScannerRegistry::register_all_default()` pushes concrete scanner instances into an internal vector.
2. `run_all` (see implementation) calls `Report::start_scanner`, invokes `scan`, then `Report::end_scanner` capturing duration.
3. `JSONWriter` aggregates global summary (counts, timings, severities) then serializes each `ScanResult` after severity filtering (via `min_severity`).

## Current Scanners
- processes: Enumerates `/proc/*/status` & `cmdline`, optional hashing (`--process-hash`) using OpenSSL (SHA256 first 1MB) if available.
- network: Parses `/proc/net/tcp{,6}`, `/proc/net/udp{,6}` with state / listen / protocol filters; severity heuristic for exposed listeners.
- kernel_params: Snapshots selected hardening sysctls (implementation not shown here for brevity).
- modules: Either enumerates each module or summarizes (`--modules-summary`). Summary collects counts, detects out‑of‑tree signatures, unsigned modules (scans or decompresses `.ko`, `.ko.{xz,gz}`), and compressed stats.
- world_writable: Walks whitelisted directories, reports world‑writable files (exclusions via substrings).
- suid: Aggregates SUID/SGID binaries by inode, collects alternate hardlink paths & escalates severity for unusual locations.
- ioc: Heuristic Indicators of Compromise (deleted executables, execution from temp, suspicious LD_* env usage, ld.so.preload anomalies, SUID in home, temp executables). Aggregates per executable for noise reduction, with allowlist downgrade via `--ioc-allow` / `--ioc-allow-file`.
- mac: Captures SELinux/AppArmor status, complain counts, unconfined critical processes (heuristic).
- compliance (conditional): Aggregates control pass/fail across selected standards (PCI DSS 4.0, HIPAA Security Rule, NIST CSF 2.0) and surfaces per-standard counts + score.

## Determinism & Ordering
- Scanners run sequentially in a fixed registration order to keep JSON ordering stable (facilitates diffing & caching).
- Metadata maps are copied to a vector then key-sorted before emission.

## Error Handling Philosophy
- Prefer silent skip on permission failure (e.g. unreadable `/proc` entries) but still record other findings.
- Symlink or file read issues inside a scanner do not abort the scanner; they simply omit data (future improvement: structured warning channel).

## Security Considerations
- Module scanner uses external decompress utilities (`xz -dc`, `gzip -dc`). Risk: shell invocation with module path. Paths derived from `modules.dep` under `/lib/modules/<release>` (trusted root-owned) mitigating injection risk (no user-controlled input). Future hardening: use liblzma / zlib streaming APIs directly.
- No outbound network connections are made; network scanner only reads procfs.
- Hashing limited to first 1MB for performance to avoid large memory footprint on huge binaries.

## Performance & Concurrency
- Currently single-threaded; `Report` already mutex-protected enabling future parallel scanner execution.
- Potential parallelization targets: processes + network + modules independently.
- IO patterns favor streaming and early caps (`--max-processes`, `--max-sockets`).

## Extensibility Guidelines
1. Create `<Name>Scanner.{h,cpp}` in `src/scanners/` implementing interface.
2. Add source file to `CMakeLists.txt` library list.
3. Register in `ScannerRegistry::register_all_default()` at an appropriate position (ordering impacts JSON diff stability).
4. Use concise, deterministic `Finding.id` (stable key for future suppression/correlation).
5. Keep heavy per-item metadata optional behind a config flag to control output volume.
6. For compliance extensions: isolate standard-specific control logic in dedicated registration helpers; ensure scores remain pure functions of counts (no hidden state) to preserve determinism.

## Future Refactors (Planned)
- Replace severity strings with `enum class Severity` plus central mapping for rank & JSON string emission.
- Introduce a lightweight `Result` / `expected` wrapper for file parsing to differentiate IO error vs absence.
- Structured warning channel (array) to surface non-fatal scanner errors distinct from security findings.
- Externalized remediation hint knowledge base (YAML) merged at JSONWriter layer (current hints are heuristic inline strings).
- Remove shell decompression dependency by embedding minimal xz/gzip readers.

## JSON Schema Versioning
- `json_schema_version`: Starts at "1" (post‑0.1.0). Increment on breaking structural changes (renaming keys, moving arrays, severity encoding shift). Backward-compatible additive fields do not increment.

## Data Flow Diagram (Logical)
```
CLI -> Config -> ScannerRegistry -> [Scanner Loop]
                                   |-> processes   -> Findings
                                   |-> network     -> Findings
                                   |-> modules     -> Findings
                                   |-> ... others  -> Findings
           Report(start/end aggregate timings) -----> JSONWriter -> stdout/file
```

## Known Limitations
- No structured distinction between collection errors and security findings yet.
- Severity taxonomy coarse; lacks numeric risk scoring (planned for Core; Intelligence layer adds risk_subscores & probability modeling).
- Compliance remediation hints currently heuristic; deeper mapping pending external knowledge base.

## Intelligence Layer (Proprietary) Overview (≈97% LOC)
Directory: `agent/` (Python). While the core emphasizes minimal, deterministic collection, the Intelligence Layer supplies the majority of domain logic and code volume.

### Functional Stages
1. Ingestion & Validation: Pydantic models parse core schema (version guards, forward‑compatible allowance for additive fields).
2. Baseline & Rarity Engine: Historical persistence (SQLite) computing rarity scores & temporal deltas.
3. Correlation Graph: Deterministic linking of low‑level findings into composite hypotheses (future DAG orchestration expansion aligns with fork prototypes).
4. Compliance Gap Normalization: Maps raw control signals to unified remediation taxonomy across standards.
5. Coverage & Tag Aggregation: MITRE technique roll‑ups, control coverage matrices.
6. Risk Re-Scoring: Combines severity, rarity, age, and correlation confidence into prioritization order.
7. Reporting Builders: Executive summaries, HTML dashboards, diff reports, machine‑readable enriched JSON.
8. Redaction / Privacy Filters: Field hashing or removal based on policy profile before export.
9. Counterfactual & Rule Refinement Utilities: Identify redundant / low-yield rules and propose tuned variants.
10. Optional Summarization Adapters: Deterministic prompt scaffolding; external model invocation is strictly opt‑in.

Design Invariants: deterministic outputs given identical input JSON + baseline state snapshot; no mutation of core artifacts; clear boundary enabling removal of `agent/` without recompilation.

Isolation Guarantees:
* No modification of core binary or runtime behavior
* Removal of `agent/` leaves all tests for the core intact
* Proprietary logic restricted to enrichment & presentation layers

## Licensing Separation
* Core (this file's described components) – MIT. Upstream canonical: https://github.com/J-mazz/sys-scan
* Intelligence Layer – Proprietary (evaluation / commercial). Pure consumer of the stable JSON contract.

Design enforcement: build graph for the core binary excludes `agent/`; enrichment imports never leak back into scanner code paths.

---
For questions or design proposals, open a GitHub Discussion or Issue tagged `design`.
