# Release Notes Template

## Highlights

- Short bullets of key features, fixes, and performance changes.

## Changes

- Added: ...
- Changed: ...
- Fixed: ...
- Security: ...

## Determinism & Reproducibility

- Built with: `-DSYS_SCAN_REPRO_BUILD=ON` and `-DSYS_SCAN_SLSA_LEVEL=1`
- Canonical JSON: `SYS_SCAN_CANON_TIME_ZERO=1 ./sys-scan --canonical > report.json`
- Hash: `sha256sum report.json` (stable under canonical mode + time zero)

## Assets

- sys-scan-graph-`<version>`-linux-x86_64.tar.gz
- sha256sums.txt [+ .asc signature if provided]

## Changelog

- Compare: <https://github.com/Mazzlabs/sys-scan-graph/compare/`prev`...`this`>
- See [CHANGELOG](./CHANGELOG.md) for structured changes and migration notes.

## Security

- Scanner is read-only; no system modifications.
- LLM provider is opt-in; redaction and governance hooks applied when enabled.
- See [SECURITY](./SECURITY.md) for disclosure and operational guidance.