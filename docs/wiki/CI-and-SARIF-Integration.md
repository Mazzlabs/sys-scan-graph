# CI and SARIF Integration

This guide shows how to run sys-scan-graph in CI and upload SARIF to GitHub Code Scanning in YOUR repository (the consumer of the scanner).

## Prerequisites

- A built binary available to the workflow (either download from Releases or build from source).
- Permissions: `security-events: write`.

## Example: Ubuntu Runner with SARIF Upload

```yaml
name: Security Scan (sys-scan-graph)
on:
  schedule:
    - cron: "0 3 * * *"
  workflow_dispatch:
  push:
    branches: [ main ]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-22.04
    steps:
      - name: Checkout repo (if relevant)
        uses: actions/checkout@v4

      - name: Download sys-scan-graph binary
        uses: robinraju/release-downloader@v1
        with:
          repository: Mazzlabs/sys-scan-graph
          latest: true
          fileName: "sys-scan-graph-*-linux-x86_64.tar.gz"
          extract: true

      - name: Run scan
        run: |
          chmod +x sys-scan
          ./sys-scan --sarif --min-severity low --modules-summary > sys-scan.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sys-scan.sarif
```

## Notes

- The scanner emits SARIF suitable for ingestion. Use `--min-severity` to tune noise.
- For deterministic artifacts, prefer `--canonical` for JSON outputs. SARIF is for visualization and triage in GitHub.
- No external data egress occurs unless you enable the Intelligence Layer with an LLM provider; by default it is off.

## Alternative: Build from Source

If you prefer to build from source in your CI:

```yaml
- name: Setup dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y build-essential cmake ninja-build

- name: Build sys-scan-graph
  run: |
    cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build -j$(nproc)

- name: Run scan
  run: ./build/sys-scan --sarif --min-severity medium > security-scan.sarif
```

## Configuration Options

### Severity Filtering

```bash
# Only report high and critical findings
./sys-scan --sarif --min-severity high > scan.sarif

# Include all findings (verbose)
./sys-scan --sarif --min-severity info > scan.sarif
```

### Scanner Modules

```bash
# Run specific modules
./sys-scan --sarif --modules-only suid,network > scan.sarif

# Skip certain modules
./sys-scan --sarif --skip-modules auditd,ebpf > scan.sarif
```

### Output Formats

```bash
# SARIF for GitHub Security tab
./sys-scan --sarif > scan.sarif

# JSON for custom processing
./sys-scan --canonical --json > scan.json

# NDJSON for streaming
./sys-scan --ndjson > scan.ndjson
```

## Integration with Other CI Systems

### GitLab CI

```yaml
scan_security:
  image: ubuntu:22.04
  before_script:
    - apt-get update && apt-get install -y wget tar
    - wget https://github.com/Mazzlabs/sys-scan-graph/releases/latest/download/sys-scan-graph-v5.0.1-linux-x86_64.tar.gz
    - tar -xzf sys-scan-graph-v5.0.1-linux-x86_64.tar.gz
  script:
    - chmod +x sys-scan
    - ./sys-scan --sarif --min-severity medium > gl-sast-sys-scan-graph.sarif
  artifacts:
    reports:
      sast: gl-sast-sys-scan-graph.sarif
```

### Jenkins

```groovy
pipeline {
    agent { docker { image 'ubuntu:22.04' } }
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    apt-get update && apt-get install -y wget tar
                    wget https://github.com/Mazzlabs/sys-scan-graph/releases/latest/download/sys-scan-graph-v5.0.1-linux-x86_64.tar.gz
                    tar -xzf sys-scan-graph-v5.0.1-linux-x86_64.tar.gz
                    chmod +x sys-scan
                    ./sys-scan --sarif --min-severity high > scan.sarif
                '''
                publishSARIF(file: 'scan.sarif')
            }
        }
    }
}
```

## Best Practices

1. **Schedule Regular Scans**: Use cron schedules for nightly security scans
2. **Adjust Severity Thresholds**: Start with `medium` or `high` to reduce noise
3. **Monitor Results**: Set up notifications for new critical findings
4. **Baseline Management**: Use `--baseline` for known acceptable findings
5. **Deterministic Builds**: Use `--canonical` for reproducible results in CI