from __future__ import annotations
"""Migration shim: raw collector report (schema v2) -> FactPack v3 structure.

Injects derived fields while preserving original severity. Severity source defaults to 'raw'.
Baseline status requires baseline deltas mapping (hash->status). If absent, marks 'unknown'.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List
from . import models
Report = models.Report
Finding = models.Finding
Correlation = models.Correlation

CATEGORY_FALLBACK = "other"

def finding_to_v3(f: Finding) -> Dict[str, Any]:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "description": f.description or "",
        "category": f.category or CATEGORY_FALLBACK,
        "tags": f.tags,
        "risk_subscores": f.risk_subscores or {},
        "correlation_refs": f.correlation_refs,
        "baseline_status": f.baseline_status or "unknown",
        "severity_source": f.severity_source or "raw",
        "allowlist_reason": f.allowlist_reason,
        "metadata": f.metadata,
    }

def correlation_to_v3(c: Correlation) -> Dict[str, Any]:
    return {
        "id": c.id,
        "title": c.title,
        "rationale": c.rationale,
        "related_finding_ids": c.related_finding_ids,
        "risk_score_delta": c.risk_score_delta,
        "tags": c.tags,
        "severity": c.severity,
        # exposure_tags optional future field
    }

def migrate_report_to_factpack_v3(report: Report, correlations: List[Correlation]) -> Dict[str, Any]:
    all_findings: List[Finding] = [f for r in report.results for f in r.findings]
    fact = {
        "fact_pack_version": "3",
        "source_schema": report.meta.json_schema_version or "2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host_id": report.meta.host_id or "unknown_host",
        "scan_id": report.meta.scan_id or "unknown_scan",
        "finding_count": len(all_findings),
        "correlation_count": len(correlations),
        "findings": [finding_to_v3(f) for f in all_findings],
        "correlations": [correlation_to_v3(c) for c in correlations]
    }
    return fact
