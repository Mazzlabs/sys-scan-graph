from __future__ import annotations
import json, hashlib, os, uuid, logging
import json as _json
from pathlib import Path
from typing import List
import yaml
import yaml as _yaml
import uuid as _uuid
from . import models
from . import knowledge
from . import rules
from . import reduction
from . import llm_provider
from . import data_governance
from . import baseline
from . import metrics
from . import canonicalize
from . import risk
from . import calibration
from . import graph_analysis
from . import endpoint_classification
from . import executors
from . import integrity
from . import audit
from . import config
import concurrent.futures

# Re-export for backward compatibility
AgentState = models.AgentState
Report = models.Report
Finding = models.Finding
EnrichedOutput = models.EnrichedOutput
ActionItem = models.ActionItem
ScannerResult = models.ScannerResult
MultiHostCorrelation = models.MultiHostCorrelation
Correlation = models.Correlation
AgentWarning = models.AgentWarning
apply_external_knowledge = knowledge.apply_external_knowledge
Correlator = rules.Correlator
DEFAULT_RULES = rules.DEFAULT_RULES
load_rules_dir = rules.load_rules_dir
reduce_all = reduction.reduce_all
get_llm_provider = llm_provider.get_llm_provider
get_data_governor = data_governance.get_data_governor
BaselineStore = baseline.BaselineStore
get_metrics_collector = metrics.get_metrics_collector
canonicalize_enriched_output_dict = canonicalize.canonicalize_enriched_output_dict
compute_risk = risk.compute_risk
load_persistent_weights = risk.load_persistent_weights
apply_probability = calibration.apply_probability
annotate_and_summarize = graph_analysis.annotate_and_summarize
classify_host_role = endpoint_classification.classify
hash_binary = executors.hash_binary
query_package_manager = executors.query_package_manager
sha256_file = integrity.sha256_file
verify_file = integrity.verify_file
log_stage = audit.log_stage
hash_text = audit.hash_text
process_feature_vector = baseline.process_feature_vector
load_config = config.load_config

logger = logging.getLogger(__name__)

# -----------------
# Internal helpers (risk recomputation & error logging)
# -----------------

def _recompute_finding_risk(f: Finding):
    """Recompute risk fields after any risk_subscores mutation.
    Safe no-op if subscores absent; logs errors instead of raising."""
    try:
        subs = getattr(f, 'risk_subscores', None)
        if not subs:
            return
        weights = load_persistent_weights()
        score, raw = compute_risk(subs, weights)
        f.risk_score = score
        f.risk_total = score
        subs["_raw_weighted_sum"] = round(raw, 3)
        f.probability_actionable = apply_probability(raw)
    except (ValueError, TypeError) as e:  # expected computation issues
        try:
            log_stage('risk_recompute_error', error=str(e), type=type(e).__name__)
        except Exception:
            pass
    except Exception as e:  # unexpected
        try:
            log_stage('risk_recompute_error_unexpected', error=str(e), type=type(e).__name__)
        except Exception:
            pass

def _log_error(stage: str, e: Exception, state: AgentState | None = None, module: str = 'pipeline', severity: str = 'warning', hint: str | None = None):
    if state is not None:
        try:
            state.agent_warnings.append(AgentWarning(module=module, stage=stage, error_type=type(e).__name__, message=str(e), severity=severity, hint=hint).model_dump())
        except Exception:
            pass
    try:
        log_stage(f'{stage}_error', error=str(e), type=type(e).__name__)
    except Exception:
        pass

# Node functions (imperative; future step: convert to LangGraph graph)

def _read_and_validate_file_size(path: Path) -> tuple[int, bytes]:
    """Read file bytes and validate size against maximum limit."""
    max_mb_env = os.environ.get('AGENT_MAX_REPORT_MB')
    try:
        max_mb = int(max_mb_env) if max_mb_env else 5
    except ValueError:
        max_mb = 5

    mc = get_metrics_collector()
    with mc.time_stage('load_report.read_bytes'):
        raw_bytes = Path(path).read_bytes()

    size_mb = len(raw_bytes) / (1024 * 1024)
    if size_mb > max_mb:
        raise ValueError(f"Report size {size_mb:.2f} MB exceeds maximum size {max_mb} MB")

    return max_mb, raw_bytes


def _decode_and_canonicalize_text(raw_bytes: bytes) -> str:
    """Decode bytes as UTF-8 and canonicalize newlines."""
    try:
        text = raw_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError as e:
        raise ValueError(f"Report is not valid UTF-8: {e}") from e

    # Canonicalize newlines (CRLF, CR -> LF)
    if '\r' in text:
        text = text.replace('\r\n', '\n').replace('\r', '\n')

    return text


def _parse_json_report(text: str) -> dict:
    """Parse the canonicalized text as JSON."""
    try:
        with get_metrics_collector().time_stage('load_report.json_parse'):
            data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Report JSON parse error: {e}") from e
    return data


def _normalize_risk_naming_migration(data: dict) -> None:
    """Normalize risk naming migration from base_severity_score to risk_score."""
    try:
        results = data.get('results') if isinstance(data, dict) else None
        if isinstance(results, list):
            for sr in results:
                findings = sr.get('findings') if isinstance(sr, dict) else None
                if not isinstance(findings, list):
                    continue
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    _normalize_finding_risk_fields(f)
    except Exception as norm_e:
        # Non-fatal; proceed to validation which may still fail with clearer message.
        try:
            log_stage('load_report.normalization_warning', error=str(norm_e), type=type(norm_e).__name__)
        except Exception:
            pass


def _normalize_finding_risk_fields(f: dict) -> None:
    """Normalize risk_score and risk_total fields for a single finding."""
    # If legacy risk_score missing but new base_severity_score present, copy.
    if 'risk_score' not in f and 'base_severity_score' in f:
        try:
            f['risk_score'] = int(f.get('base_severity_score') or 0)
        except (TypeError, ValueError):
            f['risk_score'] = 0
    # If both present but divergent (shouldn't happen), prefer explicit risk_score and log later.
    # risk_total duplication if absent
    if 'risk_total' not in f and 'risk_score' in f:
        f['risk_total'] = f['risk_score']


def _validate_report_schema(data: dict) -> Report:
    """Validate the report data against the schema."""
    try:
        with get_metrics_collector().time_stage('load_report.validate'):
            report = Report.model_validate(data)
    except Exception as e:
        raise ValueError(f"Report schema validation failed: {e}") from e
    return report


def load_report(state: AgentState, path: Path) -> AgentState:
    """Securely load and parse the raw JSON report.

    Hardening steps:
    1. Enforce maximum size (default 5 MB, override via AGENT_MAX_REPORT_MB env).
    2. Read bytes then decode strictly as UTF-8 (reject invalid sequences).
    3. Canonicalize newlines to '\n' before JSON parsing to avoid platform variance.
    """
    # Read and validate file size
    max_mb, raw_bytes = _read_and_validate_file_size(path)

    # Decode and canonicalize text
    text = _decode_and_canonicalize_text(raw_bytes)

    # Parse JSON
    data = _parse_json_report(text)

    # Store raw report
    state.raw_report = data

    # Normalize risk naming migration
    _normalize_risk_naming_migration(data)

    # Validate schema
    state.report = _validate_report_schema(data)

    return state


def _compute_finding_tags(metadata: dict, scanner: str) -> set[str]:
    """Compute base tags for a finding based on its metadata and scanner."""
    base_tags = {f"scanner:{scanner}", f"severity:{metadata.get('severity', 'unknown')}"}

    # Heuristic tags
    if metadata.get("port"):
        base_tags.add("network_port")
    if metadata.get("state") == "LISTEN":
        base_tags.add("listening")
    if metadata.get("suid") == "true":
        base_tags.add("suid")
    if metadata.get("module"):
        base_tags.add("module")
    if metadata.get("sysctl_key"):
        base_tags.add("kernel_param")

    return base_tags


def _initialize_risk_subscores(finding: Finding, severity_base: dict, policy_multiplier: dict, inferred_cat: str) -> None:
    """Initialize risk subscores for a finding based on its properties."""
    if not finding.risk_subscores:
        exposure = 0.0
        if any(t in (finding.tags or []) for t in ["listening","suid","routing","nat"]):
            # exposure scoring additive, clamp later
            if "listening" in (finding.tags or []): exposure += 1.0
            if "suid" in (finding.tags or []): exposure += 1.0
            if any(t.startswith("network_port") for t in (finding.tags or [])): exposure += 0.5
            if "routing" in (finding.tags or []): exposure += 0.5
            if "nat" in (finding.tags or []): exposure += 0.5

        cat_key = finding.category or inferred_cat or "unknown"
        impact = float(severity_base.get(finding.severity,1)) * policy_multiplier.get(cat_key,1.0)
        anomaly = 0.0  # baseline stage will add weights
        confidence = 1.0  # default; heuristic rules may lower

        finding.risk_subscores = {
            "impact": round(impact,2),
            "exposure": round(min(exposure,3.0),2),
            "anomaly": anomaly,
            "confidence": confidence
        }


def _apply_host_role_adjustments(state: AgentState) -> None:
    """Apply host role-based adjustments to finding risk scores."""
    if not state.report:
        return

    role, role_signals = classify_host_role(state.report)
    for sr in state.report.results:
        for f in sr.findings:
            f.host_role = role
            if not f.host_role_rationale:
                f.host_role_rationale = role_signals
            if f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward' and f.risk_subscores:
                impact_changed = False
                if role in {'lightweight_router','container_host'}:
                    new_imp = round(max(0.5, f.risk_subscores['impact'] * 0.6),2)
                    if new_imp != f.risk_subscores['impact']:
                        f.risk_subscores['impact'] = new_imp; impact_changed = True
                    note = f"host_role {role} => ip_forward normalized (impact adjusted)"
                elif role in {'workstation','dev_workstation'}:
                    new_imp = round(min(10.0, f.risk_subscores['impact'] * 1.2 + 0.5),2)
                    if new_imp != f.risk_subscores['impact']:
                        f.risk_subscores['impact'] = new_imp; impact_changed = True
                    note = f"host_role {role} => ip_forward unusual (impact raised)"
                else:
                    note = None
                if note:
                    if f.rationale:
                        f.rationale.append(note)
                    else:
                        f.rationale = [note]
                if impact_changed:
                    _recompute_finding_risk(f)


# Category mapping table
CAT_MAP = {
    "process": "process",
    "network": "network_socket",
    "kernel_params": "kernel_param",
    "kernel_modules": "kernel_module",
    "modules": "kernel_module",
    "world_writable": "filesystem",
    "suid": "privilege_escalation_surface",
    "ioc": "ioc",
    "mac": "mac",
    "integrity": "integrity",
    "rules": "rule_enrichment"
}

# Policy multipliers for impact based on category/policy nature
POLICY_MULTIPLIER = {
    "ioc": 2.0,
    "privilege_escalation_surface": 1.5,
    "network_socket": 1.3,
    "kernel_module": 1.2,
    "kernel_param": 1.1,
}

SEVERITY_BASE = {"info":1, "low":2, "medium":3, "high":4, "critical":5, "error":4}


def _derive_host_metadata(state: AgentState) -> None:
    """Derive host_id and scan_id from raw report metadata."""
    if not state.report:
        return

    meta_raw = state.raw_report.get("meta", {}) if state.raw_report else {}
    hostname = meta_raw.get("hostname", "unknown")
    kernel = meta_raw.get("kernel", "")

    # Derive host_id if absent
    if not state.report.meta.host_id:
        h = hashlib.sha256()
        h.update(hostname.encode())
        h.update(b"|")
        h.update(kernel.encode())
        state.report.meta.host_id = h.hexdigest()[:32]

    # Always assign a fresh scan_id
    state.report.meta.scan_id = uuid.uuid4().hex


def _merge_finding_tags(finding: Finding, base_tags: set[str]) -> None:
    """Merge base tags with existing finding tags, preserving order."""
    if not finding.tags:
        finding.tags = list(sorted(base_tags))
        return

    existing = set(finding.tags)
    for t in sorted(base_tags):
        if t not in existing:
            finding.tags.append(t)


def _initialize_finding_risk(finding: Finding, severity_base: dict, policy_multiplier: dict, inferred_cat: str) -> None:
    """Initialize risk subscores for a finding."""
    if not finding.risk_subscores:
        exposure = 0.0
        if any(t in (finding.tags or []) for t in ["listening","suid","routing","nat"]):
            if "listening" in (finding.tags or []): exposure += 1.0
            if "suid" in (finding.tags or []): exposure += 1.0
            if any(t.startswith("network_port") for t in (finding.tags or [])): exposure += 0.5
            if "routing" in (finding.tags or []): exposure += 0.5
            if "nat" in (finding.tags or []): exposure += 0.5

        cat_key = finding.category or inferred_cat or "unknown"
        impact = float(severity_base.get(finding.severity,1)) * policy_multiplier.get(cat_key,1.0)

        finding.risk_subscores = {
            "impact": round(impact,2),
            "exposure": round(min(exposure,3.0),2),
            "anomaly": 0.0,  # baseline stage will add weights
            "confidence": 1.0  # default; heuristic rules may lower
        }


def _process_finding_enrichment(sr, inferred_cat: str, severity_base: dict, policy_multiplier: dict) -> None:
    """Process enrichment for all findings in a scanner result."""
    for finding in sr.findings:
        if not finding.category:
            finding.category = inferred_cat

        # Base tags
        base_tags = _compute_finding_tags(finding.metadata or {}, sr.scanner)
        _merge_finding_tags(finding, base_tags)

        # Structured risk subscores initialization
        _initialize_finding_risk(finding, severity_base, policy_multiplier, inferred_cat)


def _perform_initial_risk_recomputation(state: AgentState) -> None:
    """Perform initial risk recomputation for findings lacking risk_score."""
    if not state.report:
        return

    mc = get_metrics_collector()
    with mc.time_stage('augment.risk_recompute_initial'):
        for sr in state.report.results:
            for finding in sr.findings:
                if finding.risk_subscores and finding.risk_score is None:
                    _recompute_finding_risk(finding)


def augment(state: AgentState) -> AgentState:
    """Derive host_id, scan_id, finding categories & basic tags without modifying core C++ schema."""
    if not state.report:
        return state

    # Derive host metadata
    _derive_host_metadata(state)

    # Iterate findings to enrich
    if not state.report or not state.report.results:
        return state

    mc = get_metrics_collector()
    with mc.time_stage('augment.iter_findings'):
        for sr in state.report.results:
            inferred_cat = CAT_MAP.get(sr.scanner.lower(), sr.scanner.lower())
            _process_finding_enrichment(sr, inferred_cat, SEVERITY_BASE, POLICY_MULTIPLIER)

    # Host role classification and adjustments
    _apply_host_role_adjustments(state)

    # Initial risk computation for findings lacking risk_score
    _perform_initial_risk_recomputation(state)

    return state


def _merge_correlation_rules(cfg) -> list:
    """Merge correlation rules from config directories and defaults with deduplication."""
    merged = []
    seen = set()
    for rd in (cfg.paths.rule_dirs or []):
        for rule in load_rules_dir(rd):
            rid = rule.get('id')
            if rid and rid in seen: continue
            merged.append(rule); seen.add(rid)
    for rule in DEFAULT_RULES:
        rid = rule.get('id')
        if rid and rid in seen: continue
        merged.append(rule); seen.add(rid)
    return merged


def _enrich_knowledge_before_correlation(state: AgentState) -> None:
    """Apply external knowledge enrichment before correlation processing."""
    mc = get_metrics_collector()
    with mc.time_stage('knowledge.enrichment'):
        apply_external_knowledge(state)


def _collect_findings_for_correlation(state: AgentState) -> List[Finding]:
    """Collect all findings from the report for correlation processing."""
    all_findings: List[Finding] = []
    if not state.report:
        return all_findings
    for r in state.report.results:
        for finding in r.findings:
            all_findings.append(finding)
    return all_findings


def _load_correlation_config_and_rules() -> tuple:
    """Load configuration and merge correlation rules."""
    cfg = load_config()
    merged = _merge_correlation_rules(cfg)
    return cfg, merged


def _apply_correlation_rules_and_metrics(all_findings: List[Finding], merged: list, mc) -> list:
    """Apply correlation rules to findings and update metrics."""
    correlator = Correlator(merged)
    with mc.time_stage('correlate.apply_rules'):
        correlations = correlator.apply(all_findings)
    mc.incr('correlate.rules_loaded', len(merged))
    mc.incr('correlate.correlations', len(correlations))
    return correlations


def _build_correlation_reference_map(correlations: list) -> dict:
    """Build a map of finding IDs to their correlation references."""
    corr_map = {}
    for c in correlations:
        for fid in c.related_finding_ids:
            corr_map.setdefault(fid, []).append(c.id)
    return corr_map


def _assign_correlation_refs_to_findings(all_findings: List[Finding], corr_map: dict) -> None:
    """Assign correlation references to findings."""
    for finding in all_findings:
        finding.correlation_refs = corr_map.get(finding.id, [])


def correlate(state: AgentState) -> AgentState:
    """Apply correlation rules to findings and build correlation references."""
    # Enrich with external knowledge first
    _enrich_knowledge_before_correlation(state)

    # Collect all findings for processing
    all_findings = _collect_findings_for_correlation(state)
    if not all_findings:
        return state

    # Load configuration and merge rules
    cfg, merged = _load_correlation_config_and_rules()

    # Apply correlation rules and update metrics
    mc = get_metrics_collector()
    state.correlations = _apply_correlation_rules_and_metrics(all_findings, merged, mc)

    # Build and assign correlation references
    corr_map = _build_correlation_reference_map(state.correlations)
    _assign_correlation_refs_to_findings(all_findings, corr_map)

    return state

def _enrich_compliance_gaps(gaps: list) -> None:
    """Enrich compliance gaps with standardized severity normalization and remediation hints."""
    if not gaps:
        return
    
    # Static mapping (could later externalize) control_id/keyword -> remediation & severity normalization
    remediation_map = {
        '2.2.4': 'Baseline and harden system services; disable or remove unused services.',
        '164.312(e)': 'Ensure transmission security: enforce TLS 1.2+, disable weak ciphers, encrypt PHI in transit.',
        '164.308(a)(1)': 'Implement risk management processes; document risk analysis and ongoing monitoring.',
        'ID.AM-01': 'Maintain accurate asset inventory (automated discovery + periodic reconciliation).',
        'PR.AC-01': 'Centralize access control; enforce MFA for privileged accounts.',
        'PR.DS-01': 'Encrypt sensitive data at rest with strong algorithms and manage keys securely.'
    }
    sev_order = {'info':0,'low':1,'medium':2,'moderate':2,'high':3,'critical':4}
    
    # Normalize severities and backfill remediation_hints
    for g in gaps:
        cid = str(g.get('control_id') or '')
        # severity normalization
        sev = (g.get('severity') or '').lower()
        if sev and sev not in sev_order:
            # map alternative labels
            if sev in {'moderate'}:
                g['severity'] = 'medium'
        # add mapped remediation if existing is missing or too short
        hint = g.get('remediation_hint') or ''
        if len(hint.strip()) < 12:
            mapped = remediation_map.get(cid)
            if mapped:
                g['remediation_hint'] = mapped


def _attach_compliance_metrics(state: AgentState, comp_sum: dict, gaps: list) -> None:
    """Attach compliance metrics to summaries."""
    # Attach into summaries.metrics (create if absent)
    if not state.summaries:
        Summaries = models.Summaries
        state.summaries = Summaries(metrics={})
    metrics = state.summaries.metrics or {}
    comp_export = {}
    for std, vals in comp_sum.items():
        # filter numeric fields
        comp_export[std] = {k: vals.get(k) for k in ['passed','failed','score','total_controls','not_applicable'] if k in vals}
    if comp_export:
        metrics['compliance_summary'] = comp_export
    if gaps:
        metrics['compliance_gap_count'] = len(gaps)
        # only include first 50 to cap size
        metrics['compliance_gaps'] = gaps[:50]
    state.summaries.metrics = metrics


def integrate_compliance(state: AgentState) -> AgentState:
    """Extract compliance summary/gaps from raw report (if present) and surface in metrics for downstream summarization.
    Adds keys:
      metrics.compliance_summary.<standard> = {passed, failed, score, total_controls}
      metrics.compliance_gap_count
      metrics.compliance_gaps (first N gap dicts)
    """
    if not state.report or not state.raw_report:
        return state
    meta = state.raw_report
    comp_sum = meta.get('compliance_summary') or {}
    gaps = meta.get('compliance_gaps') or []
    
    # Enrich gaps with standardized severity normalization & richer remediation hints if minimal
    _enrich_compliance_gaps(gaps)
    
    # Attach into summaries.metrics
    _attach_compliance_metrics(state, comp_sum, gaps)
    
    return state


def _collect_finding_pairs(state: AgentState) -> tuple[List[tuple], List[Finding]]:
    """Collect scanner-finding pairs and all findings for processing."""
    all_pairs = []
    all_findings = []
    if state.report and state.report.results:
        for sr in state.report.results:
            for f in sr.findings:
                all_pairs.append((sr.scanner, f))
                all_findings.append(f)
    return all_pairs, all_findings


def _update_baseline_deltas(store: BaselineStore, host_id: str, all_pairs: List[tuple]) -> dict:
    """Update baseline store and get deltas for all finding pairs."""
    return store.update_and_diff(host_id, all_pairs)


def _apply_anomaly_weighting(finding: Finding, d: dict | None) -> List[str]:
    """Apply anomaly weighting based on baseline status and return rationale bits."""
    rationale_bits = []
    if not finding.risk_subscores:
        return rationale_bits

    if d:
        if d["status"] == "new":
            finding.risk_subscores["anomaly"] = 2.0
            if "baseline:new" not in finding.tags:
                finding.tags.append("baseline:new")
            finding.baseline_status = "new"
            rationale_bits.append("new finding (anomaly +2)")
        else:
            prev = d.get("prev_seen_count", 1)
            # Changed vs stable heuristic: if prev_seen_count just incremented from 1->2 treat as +1 else decay
            if prev <= 2:
                finding.risk_subscores["anomaly"] = 1.0
                finding.baseline_status = "recent"
                rationale_bits.append("recent finding (anomaly +1)")
            else:
                finding.risk_subscores["anomaly"] = round(max(0.1, 1.0 / (prev)), 2)
                finding.baseline_status = "existing"
                rationale_bits.append(f"established finding (anomaly {finding.risk_subscores['anomaly']})")
                if prev >= 5:
                    # Very common => tag and downweight anomaly further contextually
                    if 'baseline:common' not in finding.tags:
                        finding.tags.append('baseline:common')
                    rationale_bits.append('very common baseline occurrence')
    return rationale_bits


def _adjust_confidence(finding: Finding) -> None:
    """Adjust confidence for IOC pattern findings."""
    if finding.risk_subscores and any(t.startswith("ioc-pattern") for t in finding.tags):
        finding.risk_subscores["confidence"] = min(finding.risk_subscores.get("confidence", 1.0), 0.7)


def _build_rationale_bits(finding: Finding, rationale_bits: List[str]) -> None:
    """Build and set rationale for finding."""
    # Impact & exposure rationale
    impact = finding.risk_subscores.get("impact") if finding.risk_subscores else 0
    exposure = finding.risk_subscores.get("exposure") if finding.risk_subscores else 0
    rationale_bits.insert(0, f"impact={impact}")
    rationale_bits.insert(1, f"exposure={exposure}")

    if not finding.rationale:
        finding.rationale = rationale_bits
    else:
        finding.rationale.extend(rationale_bits)


def _process_baseline_rarity_finding(finding: Finding, sr_scanner: str, deltas: dict) -> None:
    """Process baseline rarity for a single finding."""
    from .baseline import hashlib_sha
    h = finding.identity_hash()
    comp = hashlib_sha(sr_scanner, h)
    d = deltas.get(comp)

    # Apply anomaly weighting
    rationale_bits = _apply_anomaly_weighting(finding, d)

    # Confidence adjustment
    _adjust_confidence(finding)

    # Ensure risk_subscores exists
    if not finding.risk_subscores:
        finding.risk_subscores = {}

    # Calibrated risk using weights
    weights = load_persistent_weights()
    score, raw = compute_risk(finding.risk_subscores, weights)
    finding.risk_score = score
    finding.risk_subscores["_raw_weighted_sum"] = round(raw, 3)
    finding.probability_actionable = apply_probability(raw)

    # Build rationale
    _build_rationale_bits(finding, rationale_bits)

    finding.risk_total = finding.risk_score


def _process_baseline_rarity_loop(state: AgentState, deltas: dict) -> None:
    """Process baseline rarity for all findings."""
    if not state.report or not state.report.results:
        return

    for sr in state.report.results:
        for finding in sr.findings:
            _process_baseline_rarity_finding(finding, sr.scanner, deltas)


def baseline_rarity(state: AgentState, baseline_path: Path = Path("agent_baseline.db")) -> AgentState:
    """Update findings with rarity/anomaly score based on baseline store.
    New finding => anomaly=1.0, existing => anomaly decays toward 0.
    Exposure + impact remain unchanged; recalculates composite risk_score (simple formula for now).
    """
    if not state.report:
        return state

    import os as _os
    env_path = _os.environ.get('AGENT_BASELINE_DB')
    if env_path:
        baseline_path = Path(env_path)

    store = BaselineStore(baseline_path)
    host_id = state.report.meta.host_id or "unknown_host"

    # Collect finding pairs
    all_pairs, all_findings = _collect_finding_pairs(state)

    # Update baseline and get deltas
    deltas = _update_baseline_deltas(store, host_id, all_pairs)

    # Process baseline rarity for all findings
    _process_baseline_rarity_loop(state, deltas)

    store.conn.commit()
    return state


def _collect_process_candidates(state: AgentState) -> List[Finding]:
    """Collect candidate findings from process scanner results."""
    candidates = []
    if state.report and state.report.results:
        for sr in state.report.results:
            if sr.scanner.lower() == 'process':
                candidates.extend(sr.findings)
    return candidates


def _compute_feature_vectors(candidates: List[Finding], cfg) -> dict[str, list[float]]:
    """Compute feature vectors for process findings, with optional parallelization."""
    vecs = {}
    def _build_vec(f: Finding):
        cmd = f.metadata.get('cmdline') or f.title or f.metadata.get('process') or ''
        return f.id, process_feature_vector(cmd)

    if cfg.performance.parallel_baseline and len(candidates) > 4:
        with concurrent.futures.ThreadPoolExecutor(max_workers=cfg.performance.workers) as ex:
            for fid, v in ex.map(_build_vec, candidates):
                vecs[fid] = v
    else:
        for f in candidates:
            fid, v = _build_vec(f)
            vecs[fid] = v
    return vecs


def _apply_novelty_boost(finding: Finding, anomaly_boost: float) -> None:
    """Apply novelty boost to finding risk subscores and tags."""
    if 'process_novel' not in finding.tags:
        finding.tags.append('process_novel')

    if finding.risk_subscores:
        prev = finding.risk_subscores.get('anomaly', 0.0)
        from .risk import CAPS
        cap = CAPS.get('anomaly', 2.0)
        new_anom = round(min(prev + anomaly_boost, cap), 2)
        if new_anom != prev:
            finding.risk_subscores['anomaly'] = new_anom
            _recompute_finding_risk(finding)


def _add_near_novelty_note(finding: Finding, cid: str, dist: float) -> None:
    """Add near-novelty rationale note to finding."""
    note = f"near-novel process (cid={cid} dist={dist:.2f})"
    if finding.rationale:
        finding.rationale.append(note)
    else:
        finding.rationale = [note]


def _process_novelty_detection(candidates: List[Finding], vecs: dict[str, list[float]], store: BaselineStore, host_id: str, distance_threshold: float, anomaly_boost: float) -> None:
    """Process novelty detection for all candidate findings."""
    for f in candidates:
        vec = vecs.get(f.id)
        if vec is None:
            continue  # no vector computed

        cid, dist, is_new = store.assign_process_vector(host_id, vec, distance_threshold=float(distance_threshold))

        if is_new or dist > float(distance_threshold):
            _apply_novelty_boost(f, anomaly_boost)
            rationale_note = f"novel process cluster (cid={str(cid)} dist={dist:.2f})"
            if f.rationale:
                f.rationale.append(rationale_note)
            else:
                f.rationale = [rationale_note]
        else:
            if dist > float(distance_threshold) * 0.8:
                _add_near_novelty_note(f, str(cid), dist)


def process_novelty(state: AgentState, baseline_path: Path = Path("agent_baseline.db"), distance_threshold: float | None = None, anomaly_boost: float = 1.5) -> AgentState:
    """Assign lightweight embedding-based novelty for process findings.
    Uses config threshold if distance_threshold not provided.
    Parallelizes feature vector computation if configured (CPU-bound hashing/light transforms)."""
    if not state.report:
        return state

    cfg = load_config()
    if distance_threshold is None:
        # Fallback to configured threshold; if missing or None, choose conservative default 1.0
        dt_cfg = getattr(cfg.thresholds, 'process_novelty_distance', None)
        distance_threshold = float(dt_cfg) if dt_cfg is not None else 1.0

    env_path = os.environ.get('AGENT_BASELINE_DB')
    if env_path:
        baseline_path = Path(env_path)

    store = BaselineStore(baseline_path)
    host_id = state.report.meta.host_id or "unknown_host"

    # Collect candidate findings
    candidates = _collect_process_candidates(state)
    if not candidates:
        return state

    # Pre-compute feature vectors (parallel if enabled)
    vecs = _compute_feature_vectors(candidates, cfg)

    # Process novelty detection
    _process_novelty_detection(candidates, vecs, store, host_id, distance_threshold, anomaly_boost)

    return state


def _flatten_findings(state: AgentState) -> List[Finding]:
    """Flatten all findings from report results preserving order."""
    ordered: List[Finding] = []
    if state.report and state.report.results:
        for r in state.report.results:
            ordered.extend(r.findings)
    return ordered


def _collect_suid_indices(ordered: List[Finding]) -> List[tuple]:
    """Collect indices of new SUID findings."""
    suid_indices = []
    for idx, f in enumerate(ordered):
        if 'suid' in (f.tags or []) and any(t == 'baseline:new' for t in (f.tags or [])):
            suid_indices.append((idx, f))
    return suid_indices


def _collect_ip_forward_indices(ordered: List[Finding]) -> List[tuple]:
    """Collect indices of IP forwarding enabled findings."""
    ip_forward_indices = []
    for idx, f in enumerate(ordered):
        if f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward':
            val = str(f.metadata.get('value') or f.metadata.get('desired') or f.metadata.get('current') or '')
            if val in {'1','true','enabled'}:
                ip_forward_indices.append((idx, f))
    return ip_forward_indices


def _check_sequence_trigger(suid_indices: List[tuple], ip_forward_indices: List[tuple]) -> bool:
    """Check if any SUID precedes any IP forwarding finding."""
    if not suid_indices or not ip_forward_indices:
        return False
    trigger_pairs = [(s,i) for (s,_) in suid_indices for (i,_) in ip_forward_indices if s < i]
    return bool(trigger_pairs)


def _build_related_finding_ids(suid_indices: List[tuple], ip_forward_indices: List[tuple]) -> List[str]:
    """Build list of related finding IDs for correlation."""
    related = []
    for (s_idx, s_f) in suid_indices[:3]:
        related.append(s_f.id)
    for (i_idx, i_f) in ip_forward_indices[:2]:
        related.append(i_f.id)
    return related


def _create_sequence_correlation(related: List[str], existing_count: int) -> Correlation:
    """Create a sequence anomaly correlation."""
    # Deterministic ID: sequence_anom_<n>
    corr_id = f'sequence_anom_{existing_count + 1}'
    corr = Correlation(
        id=corr_id,
        title='Suspicious Sequence: New SUID followed by IP forwarding enabled',
        rationale='Heuristic: newly introduced SUID binary preceded enabling IP forwarding in same scan',
        related_finding_ids=related,
        risk_score_delta=8,
        tags=['sequence_anomaly','routing','privilege_escalation_surface'],
        severity='high'
    )
    return corr


def _add_correlation_refs(state: AgentState, corr: Correlation, ordered: List[Finding]) -> None:
    """Add correlation references to related findings."""
    for f in ordered:
        if f.id in corr.related_finding_ids:
            if corr.id not in (f.correlation_refs or []):
                if f.correlation_refs is None:
                    f.correlation_refs = []
                f.correlation_refs.append(corr.id)


def sequence_correlation(state: AgentState) -> AgentState:
    """Detect suspicious temporal sequences inside a single scan.
    Current heuristic pattern:
      1. New SUID binary (tag baseline:new + suid) appears
      2. net.ipv4.ip_forward kernel param enabled (value=1) in same scan after the SUID finding order.
    If both occur, emit synthetic correlation with tag sequence_anomaly.
    Ordering proxy: we use appearance order in report results since per-scanner timestamps absent.
    """
    if not state.report:
        return state

    # Flatten findings preserving order
    ordered = _flatten_findings(state)

    # Collect relevant finding indices
    suid_indices = _collect_suid_indices(ordered)
    ip_forward_indices = _collect_ip_forward_indices(ordered)

    # Check for sequence trigger
    if _check_sequence_trigger(suid_indices, ip_forward_indices):
        # Build correlation referencing the involved findings
        related = _build_related_finding_ids(suid_indices, ip_forward_indices)

        # Avoid duplicate correlation creation
        already = any(c.related_finding_ids == related and 'sequence_anomaly' in (c.tags or []) for c in state.correlations)
        if not already:
            # Count existing sequence anomalies
            existing_count = len([c for c in state.correlations if 'sequence_anomaly' in (c.tags or []) and c.id.startswith('sequence_anom_')])
            corr = _create_sequence_correlation(related, existing_count)
            state.correlations.append(corr)

            # Back-reference on findings
            _add_correlation_refs(state, corr, ordered)

    return state


def reduce(state: AgentState) -> AgentState:
    if not state.report:
        return state
    all_findings: List[Finding] = [f for r in state.report.results for f in r.findings]
    mc = get_metrics_collector()
    with mc.time_stage('reduce.reduce_all'):
        state.reductions = reduce_all(all_findings).model_dump()
    return state


def _calculate_risk_aggregation(all_findings: List[Finding], threshold: float) -> tuple[bool, float, bool]:
    """Calculate risk aggregation and determine if summarization should be skipped."""
    high_med_sum = 0
    new_found = False
    for f in all_findings:
        sev = f.severity.lower()
        if sev in {"medium","high","critical"}:
            # Exclude operational_error pseudo-findings from security risk aggregation
            if not getattr(f, 'operational_error', False):
                high_med_sum += (f.risk_total or f.risk_score or 0)
        if any(t == 'baseline:new' for t in (f.tags or [])):
            new_found = True
    skip = (high_med_sum < threshold) and (not new_found)
    return skip, high_med_sum, new_found


def _prepare_llm_inputs(state: AgentState, governor) -> tuple:
    """Prepare and redact inputs for LLM provider."""
    # Redact inputs before passing to provider (governance enforcement)
    try:
        from .redaction import redact_reductions
        red_reductions_dict = redact_reductions(state.reductions)
        # Convert back to Reductions object for LLM provider
        from .models import Reductions
        red_reductions = Reductions(**red_reductions_dict)
    except ImportError:
        # Fallback to data governance if redaction module not available
        red_reductions = governor.redact_for_llm(state.reductions)
        # If it's still a dict, try to convert to Reductions object
        if isinstance(red_reductions, dict):
            from .models import Reductions
            red_reductions = Reductions(**red_reductions)

    red_correlations = [governor.redact_for_llm(c) for c in state.correlations]
    red_actions = [governor.redact_for_llm(a) for a in state.actions]

    return red_reductions, red_correlations, red_actions


def _add_token_accounting(state: AgentState) -> None:
    """Add token accounting and cost calculation to summaries metrics."""
    try:
        # Token accounting model removed / deprecated; inline dict if needed in future.
        m = state.summaries.metrics or {}
        state.summaries.metrics = state.summaries.metrics or {}
        state.summaries.metrics['token_accounting'] = {
            'prompt_tokens': m.get('tokens_prompt',0),
            'completion_tokens': m.get('tokens_completion',0),
            'cached': bool(m.get('skipped')),
            'unit_cost_prompt': float(os.environ.get('AGENT_COST_PROMPT_PER_1K', '0') or 0)/1000.0,
            'unit_cost_completion': float(os.environ.get('AGENT_COST_COMPLETION_PER_1K','0') or 0)/1000.0,
        }
        state.summaries.metrics['estimated_cost'] = round(
            state.summaries.metrics['token_accounting']['prompt_tokens'] * state.summaries.metrics['token_accounting']['unit_cost_prompt'] +
            state.summaries.metrics['token_accounting']['completion_tokens'] * state.summaries.metrics['token_accounting']['unit_cost_completion'], 6
        )
    except Exception:
        pass


def _compute_attack_coverage(state: AgentState) -> None:
    """Compute and attach ATT&CK coverage information to summaries."""
    try:
        mapping = _load_attack_mapping()
        if state.report and state.summaries:
            covered = {}
            all_tags = set()
            for r in state.report.results:
                for f in r.findings:
                    for t in (f.tags or []):
                        all_tags.add(t)
            for c in state.correlations:
                for t in (c.tags or []):
                    all_tags.add(t)
            techniques = set()
            tag_hits = {}
            for tag in all_tags:
                techs = mapping.get(tag)
                if not techs:
                    continue
                if isinstance(techs, list):
                    for tid in techs:
                        techniques.add(tid)
                elif isinstance(techs, str):
                    techniques.add(techs)
                tag_hits[tag] = techs
            state.summaries.attack_coverage = {
                'technique_count': len(techniques),
                'techniques': sorted(techniques),
                'tag_hits': tag_hits
            }
    except Exception as e:
        _log_error('attack_coverage', e, state)


def _initialize_summarize_vars(state: AgentState):
    """Initialize variables for summarize function."""
    client = get_llm_provider()
    governor = get_data_governor()
    cfg = load_config()
    threshold = cfg.thresholds.summarization_risk_sum
    all_findings = [f for r in state.report.results for f in r.findings] if state.report else []
    return client, governor, cfg, threshold, all_findings


def _determine_skip_condition(all_findings: List[Finding], threshold: float) -> tuple[bool, float, bool]:
    """Determine if summarization should be skipped based on risk aggregation."""
    skip, high_med_sum, new_found = _calculate_risk_aggregation(all_findings, threshold)
    return skip, high_med_sum, new_found


def _call_llm_summarize(client, red_reductions, red_correlations, red_actions, skip: bool, prev):
    """Call the LLM summarize method and handle result."""
    summaries_result = client.summarize(red_reductions, red_correlations, red_actions, skip=skip, previous=prev, skip_reason="low_risk_no_change" if skip else None, baseline_context=None)
    # Handle both tuple and direct return for backward compatibility
    if isinstance(summaries_result, tuple):
        summaries, provider_metadata = summaries_result
    else:
        summaries = summaries_result
        provider_metadata = None
    return summaries, provider_metadata


def _post_process_summaries(state: AgentState, governor):
    """Post-process summaries with accounting, redaction, coverage, and hypotheses."""
    # Attach token accounting snapshot for future cost modeling
    _add_token_accounting(state)
    # Scrub narrative fields prior to persistence/output
    state.summaries = governor.redact_output_narratives(state.summaries)
    # ATT&CK coverage computation
    _compute_attack_coverage(state)
    # Experimental causal hypotheses
    try:
        if state.summaries:
            state.summaries.causal_hypotheses = generate_causal_hypotheses(state)
    except Exception as e:
        _log_error('causal_hypotheses', e, state)


def summarize(state: AgentState) -> AgentState:
    """Generate executive summaries using LLM provider."""
    # Initialize variables
    client, governor, cfg, threshold, all_findings = _initialize_summarize_vars(state)

    # Determine skip condition
    skip, high_med_sum, new_found = _determine_skip_condition(all_findings, threshold)
    prev = getattr(state, 'summaries', None)

    # Prepare and redact inputs for LLM
    red_reductions, red_correlations, red_actions = _prepare_llm_inputs(state, governor)

    # Call LLM summarize
    mc = get_metrics_collector()
    with mc.time_stage('summarize.llm'):
        state.summaries, provider_metadata = _call_llm_summarize(client, red_reductions, red_correlations, red_actions, skip, prev)

    # Post-process summaries
    _post_process_summaries(state, governor)

    return state


def actions(state: AgentState) -> AgentState:
    items: List[ActionItem] = []
    # Simple deterministic mapping examples
    mc = get_metrics_collector()
    with mc.time_stage('actions.build'):
        for c in state.correlations:
            if "routing" in c.tags:
                items.append(ActionItem(priority=len(items)+1, action="Confirm intent for routing/NAT configuration; disable if not required.", correlation_refs=[c.id]))
    # Baseline noise example: if many SUID unexpected
    if state.reductions.get('suid_summary') and state.reductions['suid_summary'].get("unexpected_suid"):
        items.append(ActionItem(priority=len(items)+1, action="Review unexpected SUID binaries; remove SUID bit if unnecessary.", correlation_refs=[]))
    mc.incr('actions.count', len(items))
    state.actions = items
    return state


def _verify_file_integrity(raw_path: Path, sha: str | None) -> dict | None:
    """Verify file integrity using signature verification if key provided."""
    integrity_status = None
    try:
        # If verification key provided via env, attempt signature verification
        vkey = os.environ.get('AGENT_VERIFY_KEY_B64')
        if raw_path.exists():
            if vkey:
                integrity_status = verify_file(raw_path, vkey)
            else:
                # minimal status with sha only
                integrity_status = {'sha256_actual': sha}
    except Exception as e:
        _log_error('integrity_verify', e, severity='error', hint='Check signature key / file permissions')
        integrity_status = {'sha256_actual': sha, 'error': 'integrity_check_failed'}
    return integrity_status


def _process_performance_metrics_and_baseline(out: EnrichedOutput, perf_snap: dict, state: AgentState) -> None:
    """Process performance metrics, baseline regression detection, and surface summary metrics."""
    assert out.enrichment_results is not None  # Guaranteed by caller
    baseline_path = os.environ.get('AGENT_PERF_BASELINE_PATH', 'artifacts/perf_baseline.json')
    threshold_env = os.environ.get('AGENT_PERF_REGRESSION_PCT', '30')
    try:
        threshold = max(0.0, float(threshold_env))/100.0
    except ValueError:
        threshold = 0.30
    from .metrics import MetricsCollector
    base = MetricsCollector.load_baseline(baseline_path)
    regressions = MetricsCollector.compare_to_baseline(perf_snap, base or {}, threshold) if base else []
    perf_snap['baseline_regressions'] = regressions
    perf_snap['baseline_threshold_pct'] = threshold*100
    out.enrichment_results['perf'] = perf_snap
    # Save current snapshot as new baseline (rolling)
    MetricsCollector.save_baseline(baseline_path, perf_snap)
    # Surface summary perf metrics
    if out.summaries:
        totals = perf_snap.get('durations', {})
        total_time = sum(v.get('total',0) for v in totals.values())
        slowest = None
        slowest_time = -1
        for stage, stats in totals.items():
            if stats.get('total',0) > slowest_time:
                slowest = stage
                slowest_time = stats.get('total',0)
        metrics_map = out.summaries.metrics or {}
        metrics_map.update({
            'perf.total_ms': total_time,
            'perf.slowest_stage': slowest,
            'perf.slowest_ms': slowest_time,
            'perf.regression_count': len(regressions)
        })
        out.summaries.metrics = metrics_map


def _apply_canonical_ordering(out: EnrichedOutput) -> None:
    """Apply deterministic canonical ordering to entire output."""
    try:
        out_dict = out.model_dump()
        canon = canonicalize_enriched_output_dict(out_dict)
        from .models import EnrichedOutput as _EO, Summaries
        # Ensure summaries is converted back to Summaries object
        if 'summaries' in canon and isinstance(canon['summaries'], dict):
            canon['summaries'] = Summaries(**canon['summaries'])
        out = _EO(**canon)
    except Exception:
        # On failure, fall back to original out
        pass


def build_output(state: AgentState, raw_path: Path) -> EnrichedOutput:
    sha = hashlib.sha256(Path(raw_path).read_bytes()).hexdigest() if raw_path.exists() else None
    integrity_status = _verify_file_integrity(raw_path, sha)
    flat_findings = []
    if state.report:
        for r in state.report.results:
            flat_findings.extend(r.findings)
    # Correlation graph metrics
    mc = get_metrics_collector()
    with mc.time_stage('graph.annotate'):
        graph_meta = annotate_and_summarize(state)
    out = EnrichedOutput(
        correlations=state.correlations,
        reductions=state.reductions,
        summaries=state.summaries,
        actions=state.actions,
        raw_reference=sha,
        enriched_findings=flat_findings,
        correlation_graph=graph_meta if graph_meta else None,
        followups=state.followups if state.followups else None,
    enrichment_results=state.enrichment_results or None,
    multi_host_correlation=state.multi_host_correlation or None,
    integrity=integrity_status
    )
    if out.enrichment_results is None:
        out.enrichment_results = {}
    if state.agent_warnings:
        out.enrichment_results['agent_warnings'] = state.agent_warnings
    # Performance metrics and baseline regression detection
    perf_snap = mc.snapshot()
    _process_performance_metrics_and_baseline(out, perf_snap, state)
    # Populate meta.analytics (INT-OBS-001) with concise summary (avoid large arrays)
    try:
        if state.report and state.report.meta:
            # Analytics field not in Meta model, skip for now
            pass
    except Exception:
        pass
    # Apply deterministic canonical ordering to entire output
    _apply_canonical_ordering(out)
    return out


# -----------------
# Optional External Corpus Integration (Hugging Face datasets)
# -----------------

def _augment_with_corpus_insights(state: AgentState):
    """Optionally load external cybersecurity corpora (if token & pandas available) to
    attach high-level corpus metrics to summaries.metrics for adaptive reasoning.

    Controlled by env AGENT_LOAD_HF_CORPUS=1. Lightweight: only counts / sample hash.
    Avoids loading if already present in metrics. Silent (logs on error)."""
    if not os.environ.get('AGENT_LOAD_HF_CORPUS'):
        return state
    try:
        import hf_loader
    except Exception as e:  # module absent
        _log_error('corpus_import', e)
        return state
    try:
        jsonl_df = hf_loader.load_cybersec_jsonl()
        parquet_df = hf_loader.load_cybersec_parquet()
        j_rows = int(len(jsonl_df)) if jsonl_df is not None else None
        p_rows = int(len(parquet_df)) if parquet_df is not None else None
        # Minimal content fingerprint (no sensitive data): column name hash
        import hashlib as _hl
        def _col_fprint(df):
            if df is None: return None
            h = _hl.sha256()
            for c in sorted(df.columns):
                h.update(c.encode())
            return h.hexdigest()[:16]
        metrics_add = {
            'corpus.jsonl_rows': j_rows,
            'corpus.parquet_rows': p_rows,
            'corpus.jsonl_schema_fprint': _col_fprint(jsonl_df),
            'corpus.parquet_schema_fprint': _col_fprint(parquet_df)
        }
        if state.summaries:
            base = state.summaries.metrics or {}
            # Do not overwrite existing keys unless None
            for k,v in metrics_add.items():
                if k not in base or base[k] is None:
                    base[k] = v
            state.summaries.metrics = base
    except Exception as e:
        _log_error('corpus_insights', e)
    return state


def _check_drift_and_routing_conditions(state: AgentState) -> tuple[bool, bool]:
    """Check if metric drift findings and routing correlations are present."""
    drift_present = any('metric_drift' in (f.tags or []) for r in (state.report.results if state.report else []) for f in r.findings)
    routing_corr = any('routing' in c.tags for c in state.correlations)
    return drift_present, routing_corr


def _deduplicate_hypotheses(hyps: list, max_hypotheses: int) -> list:
    """Deduplicate hypotheses by summary and cap at max_hypotheses."""
    out = []
    seen = set()
    for h in hyps:
        if h['summary'] in seen:
            continue
        seen.add(h['summary'])
        out.append(h)
        if len(out) >= max_hypotheses:
            break
    return out


def generate_causal_hypotheses(state: AgentState, max_hypotheses: int = 3) -> list[dict]:
    """Generate speculative causal hypotheses from correlations & findings.
    Heuristics only (deterministic):
      - sequence_anomaly => privilege escalation chain.
      - module_propagation => lateral movement via module.
      - presence of metric_drift finding + routing correlation => config change root cause.
    Mark all as speculative with low confidence.
    """
    hyps = []
    for c in state.correlations:
        if 'sequence_anomaly' in c.tags:
            hyps.append({
                'id': f"hyp_{len(hyps)+1}",
                'summary': 'Potential privilege escalation chain (new SUID then IP forwarding)',
                'rationale': [c.rationale],
                'confidence': 'low',
                'speculative': True
            })
        if 'module_propagation' in c.tags:
            hyps.append({
                'id': f"hyp_{len(hyps)+1}",
                'summary': 'Possible lateral movement via near-simultaneous kernel module deployment',
                'rationale': [c.rationale or 'simultaneous module emergence across hosts'],
                'confidence': 'low',
                'speculative': True
            })
    
    # Check for drift and routing conditions
    drift_present, routing_corr = _check_drift_and_routing_conditions(state)
    if drift_present and routing_corr:
        hyps.append({
            'id': f"hyp_{len(hyps)+1}",
            'summary': 'Configuration change likely triggered routing and risk metric drift',
            'rationale': ['metric drift finding plus routing-related correlation(s)'],
            'confidence': 'low',
            'speculative': True
        })
    
    # Deduplicate by summary, cap
    return _deduplicate_hypotheses(hyps, max_hypotheses)


def _load_attack_mapping(path: Path | None = None) -> dict:
    if path is None:
        # Use path relative to this file's directory
        path = Path(__file__).parent.parent / 'attack_mapping.yaml'
    try:
        if not path.exists():
            return {}
        data = _yaml.safe_load(path.read_text()) or {}
        return data
    except Exception:
        return {}


def _detect_metric_drift(state: AgentState) -> None:
    """Detect and synthesize findings for metric drift anomalies."""
    if not state.report or not state.report.meta or not state.report.meta.host_id or not state.report.meta.scan_id:
        return

    host_id = state.report.meta.host_id
    scan_id = state.report.meta.scan_id

    # Derive metrics from current findings
    all_findings = [f for r in state.report.results for f in r.findings]
    total_findings = len(all_findings)
    high_count = sum(1 for f in all_findings if f.severity.lower() in {"high","critical"})
    med_hi_risk_sum = sum((f.risk_total or f.risk_score or 0) for f in all_findings
                          if f.severity.lower() in {"medium","high","critical"}
                          and not getattr(f, 'operational_error', False))

    metrics = {
        'finding.count.total': float(total_findings),
        'finding.count.high': float(high_count),
        'risk.sum.medium_high': float(med_hi_risk_sum)
    }

    store = BaselineStore(Path("agent_baseline.db"))
    metric_stats = store.record_metrics(host_id, scan_id, metrics, history_limit=10)

    # Process drift detection with configurable threshold
    drift_threshold = 2.5
    drift_findings = []

    for mname, stats in metric_stats.items():
        if _is_metric_drift_triggered(stats, drift_threshold):
            drift_finding = _create_drift_finding(mname, stats)
            if drift_finding:
                drift_findings.append(drift_finding)

    # Add drift findings to report if any detected
    if drift_findings:
        sr = ScannerResult(scanner='metric_drift', finding_count=len(drift_findings), findings=drift_findings)
        state.report.results.append(sr)


def _is_metric_drift_triggered(stats: dict, threshold: float) -> bool:
    """Determine if metric statistics indicate a drift anomaly."""
    z = stats.get('z')
    hist_n = stats.get('history_n', 0)

    # Accept drift if enough history for z-score analysis
    if z is not None and hist_n >= 2 and abs(z) >= threshold:
        return True

    # Early detection using simple delta heuristic
    elif z is None and hist_n >= 2 and stats.get('mean') is not None:
        mean = stats['mean']
        val = stats['value']
        # 100% increase heuristic for early detection
        if mean and (val - mean) / mean >= 1.0:
            return True

    return False


def _create_drift_finding(metric_name: str, stats: dict) -> Finding | None:
    """Create a synthetic finding for detected metric drift."""
    try:
        fid = f"metric:{metric_name}:drift"
        z_for_sev = abs(stats.get('z', 0))

        # Calculate anomaly score
        from .risk import CAPS
        anomaly_cap = CAPS.get('anomaly', 2.0)
        raw_anom = (abs(stats.get('z', 0)) / 3.0) if stats.get('z') is not None else 1.0
        anomaly_val = min(anomaly_cap, raw_anom)

        drift = Finding(
            id=fid,
            title="Metric Drift Detected",
            severity="medium" if z_for_sev < 5 else "high",
            risk_score=0,
            metadata={
                'metric': metric_name,
                'z': stats.get('z'),
                'value': stats['value'],
                'mean': stats['mean'],
                'std': stats['std']
            },
            category='telemetry',
            tags=['synthetic','metric_drift'],
            risk_subscores={'impact': 3.0, 'exposure': 0.0, 'anomaly': anomaly_val, 'confidence': 0.9},
            baseline_status='new',
            metric_drift=stats
        )

        # Compute risk for synthetic finding
        weights = load_persistent_weights()
        score, raw = compute_risk(drift.risk_subscores or {}, weights)
        drift.risk_score = score
        drift.risk_total = score
        drift.probability_actionable = apply_probability(raw)

        # Set rationale based on available statistics
        if stats.get('z') is not None:
            drift.rationale = [f"metric {metric_name} drift z={stats['z']:.2f} value={stats['value']} mean={stats['mean']:.2f} std={stats['std']:.2f}"]
        else:
            drift.rationale = [f"metric {metric_name} early drift value={stats['value']} mean={stats['mean']:.2f} (delta >=100%)"]

        return drift
    except Exception:
        return None


def _process_multi_host_correlations(state: AgentState) -> None:
    """Process cross-host correlations for module propagation anomalies."""
    if not state.report or not state.report.results:
        return

    try:
        store = BaselineStore(Path(os.environ.get('AGENT_BASELINE_DB','agent_baseline.db')))
        recent = store.recent_module_first_seen(within_seconds=86400)
        threshold = int(os.environ.get('PROPAGATION_HOST_THRESHOLD','3'))

        for module, hosts in recent.items():
            if len(hosts) >= threshold:
                # Create multi-host correlation
                corr = MultiHostCorrelation(
                    type='module_propagation',
                    key=module,
                    host_ids=hosts,
                    rationale=f"Module '{module}' first appeared on {len(hosts)} hosts within 24h window"
                )
                state.multi_host_correlation.append(corr)

                # Create synthetic finding
                fid = f"multi_host_module:{module}"
                synth = Finding(
                    id=fid,
                    title=f"Potential Propagation: module {module}",
                    severity='medium',
                    risk_score=0,
                    metadata={'module': module, 'host_cluster_size': len(hosts)},
                    category='cross_host',
                    tags=['synthetic','cross_host','module_propagation'],
                    risk_subscores={'impact': 5.0, 'exposure': 0.0, 'anomaly': min(1.5, (__import__('risk', fromlist=['CAPS']).CAPS.get('anomaly',2.0))), 'confidence': 0.8},
                    baseline_status='new'
                )
                _recompute_finding_risk(synth)
                synth.rationale = [f"Module simultaneously observed on {len(hosts)} hosts (>= {threshold})"]

                # Add to report results
                added = False
                for sr in state.report.results:
                    if sr.scanner == 'multi_host':
                        sr.findings.append(synth)
                        sr.finding_count += 1
                        added = True
                        break
                if not added:
                    state.report.results.append(ScannerResult(scanner='multi_host', finding_count=1, findings=[synth]))
    except Exception as e:
        _log_error('multi_host_correlation', e)


def _plan_followups(state: AgentState) -> None:
    """Plan follow-up actions for findings that require additional investigation."""
    if not state.report:
        return

    for r in state.report.results:
        for f in r.findings:
            if _should_follow_up(f, r.scanner):
                plan = ["hash_binary", "query_package_manager"]
                results = {}
                bin_path = f.metadata.get('exe') or f.metadata.get('path')
                if bin_path:
                    results['hash_binary'] = hash_binary(bin_path)
                    results['query_package_manager'] = query_package_manager(bin_path)
                from .models import FollowupResult
                state.followups.append(FollowupResult(finding_id=f.id, plan=plan, results=results))
                try:
                    log_stage('followup_execute', finding_id=f.id, plan=";".join(plan))
                except Exception as e:
                    _log_error('followup_execute', e)


def _should_follow_up(finding: Finding, scanner: str) -> bool:
    """Determine if a finding should have follow-up actions."""
    # Mark certain IOC executables as development tools
    exe_path = finding.metadata.get('exe') or ''
    if exe_path and any(tok in exe_path for tok in ['cpptools','python-env-tools']):
        if 'ioc:development-tool' not in finding.tags:
            finding.tags.append('ioc:development-tool')

    # Follow up on development tools or SUID findings
    if any(t == 'ioc:development-tool' for t in (finding.tags or [])) and not finding.allowlist_reason:
        return True
    if scanner.lower() == 'suid' and finding.metadata.get('path'):
        return True

    return False


def _process_followup_results(state: AgentState) -> None:
    """Process follow-up results and apply trust-based severity adjustments."""
    if not state.followups or not state.report:
        return

    # Load trusted manifest
    trust_path = Path(__file__).parent / 'knowledge' / 'trusted_binaries.yaml'
    trusted = {}
    if trust_path.exists():
        try:
            trusted = yaml.safe_load(trust_path.read_text()) or {}
        except Exception as e:
            _log_error('trusted_manifest_load', e)
            trusted = {}

    trust_map = trusted.get('trusted', {})
    report_results = state.report.results or []

    # Build hash->(tool_key, downgrade) index for faster lookup
    hash_index = {}
    for tk, meta in trust_map.items():
        for hv in meta.get('sha256', []) or []:
            hash_index[hv] = (tk, meta.get('downgrade_severity_to'))

    for fu in state.followups:
        fobj = _find_finding_by_id(report_results, fu.finding_id)
        if not fobj:
            continue

        state.enrichment_results.setdefault(fu.finding_id, fu.results)

        # Evaluate trust based on hash
        hdata = fu.results.get('hash_binary') or {}
        sha = hdata.get('sha256')
        if sha:
            _apply_trust_adjustment(fobj, sha, hash_index, trust_map)


def _find_finding_by_id(report_results: List[ScannerResult], finding_id: str) -> Finding | None:
    """Find a finding by ID across all scanner results."""
    for r in report_results:
        for f in r.findings:
            if f.id == finding_id:
                return f
    return None


def _apply_trust_adjustment(finding: Finding, sha: str, hash_index: dict, trust_map: dict) -> None:
    """Apply severity adjustment if finding matches trusted binary hash."""
    # First, direct hash index lookup
    trust_entry = hash_index.get(sha)
    tool_key = None
    downgrade = None

    if trust_entry:
        tool_key, downgrade = trust_entry
    else:
        # Fallback heuristic by tool key substring
        title_lower = finding.title.lower()
        path_val = finding.metadata.get('exe') or ''
        if 'cpptools' in title_lower or 'cpptools' in path_val:
            tool_key = 'cpptools'
            meta = trust_map.get(tool_key) or {}
            if sha in (meta.get('sha256') or []):
                downgrade = meta.get('downgrade_severity_to')

    if tool_key and downgrade and downgrade != finding.severity:
        old = finding.severity
        finding.severity = downgrade
        finding.severity_source = 'trusted_binary'

        rationale_msg = f"trusted binary hash matched ({tool_key}); severity {old}->{downgrade}"
        if finding.rationale:
            finding.rationale.append(rationale_msg)
        else:
            finding.rationale = [rationale_msg]

        # Update tags
        if 'trusted_binary' not in (finding.tags or []):
            finding.tags.append('trusted_binary')

        sev_tag = f"severity:{downgrade}"
        if finding.tags and sev_tag not in finding.tags:
            finding.tags.append(sev_tag)

        # Recompute risk
        _recompute_finding_risk(finding)


def _execute_pipeline_stage(state: AgentState, stage_func, stage_name: str, **log_kwargs):
    """Execute a pipeline stage with error handling and logging."""
    try:
        result = stage_func(state)
        log_stage(stage_name, **log_kwargs)
        return result
    except Exception as e:
        _log_error(f'{stage_name}_error', e)
        return state


def _execute_pipeline_stage_with_count(state: AgentState, stage_func, stage_name: str, count_func):
    """Execute a pipeline stage that produces countable results."""
    try:
        result = stage_func(state)
        count = count_func(result) if count_func else 0
        log_stage(stage_name, **{stage_name: count})
        return result
    except Exception as e:
        _log_error(f'{stage_name}_log', e)
        return state


def _execute_void_pipeline_stage(state: AgentState, stage_func, stage_name: str):
    """Execute a pipeline stage that doesn't return state (void function)."""
    try:
        stage_func(state)
        log_stage(stage_name)
    except Exception as e:
        _log_error(stage_name, e)


def _count_findings(state: AgentState) -> int:
    """Count total findings in the report."""
    if not state.report or not state.report.results:
        return 0
    return sum(len(r.findings) for r in state.report.results)


def _count_correlations(state: AgentState) -> int:
    """Count correlations."""
    return len(state.correlations)


def _count_actions(state: AgentState) -> int:
    """Count actions."""
    return len(state.actions)


def _count_top_findings(state: AgentState) -> int:
    """Count top findings in reductions."""
    return len(state.reductions.get('top_findings', []))


def _extract_summarize_metrics(state: AgentState) -> dict:
    """Extract metrics from summaries for logging."""
    metrics = (state.summaries.metrics if state.summaries else {}) or {}
    return {
        'tokens_prompt': metrics.get('tokens_prompt'),
        'tokens_completion': metrics.get('tokens_completion')
    }


def run_pipeline(report_path: Path) -> EnrichedOutput:
    """Execute the complete security scanning pipeline."""
    state = AgentState()

    # Load and validate report
    state = load_report(state, report_path)
    _execute_pipeline_stage(state, lambda s: s, 'load_report',
                          file=str(report_path),
                          sha256=hashlib.sha256(report_path.read_bytes()).hexdigest())

    # Augment findings with metadata and risk scores
    state = _execute_pipeline_stage_with_count(state, augment, 'augment', _count_findings)

    # Integrate compliance data
    state = _execute_pipeline_stage(state, integrate_compliance, 'integrate_compliance')

    # Apply security policies
    state = _execute_pipeline_stage(state, apply_policy, 'policy_enforce')

    # Correlate findings
    state = _execute_pipeline_stage_with_count(state, correlate, 'correlate', _count_correlations)

    # Detect temporal sequences
    state = _execute_pipeline_stage(state, sequence_correlation, 'sequence_correlation')

    # Apply baseline rarity analysis
    state = _execute_pipeline_stage(state, baseline_rarity, 'baseline_rarity')

    # Process novelty detection
    state = _execute_pipeline_stage(state, process_novelty, 'process_novelty')

    # Detect metric drift anomalies
    _execute_void_pipeline_stage(state, _detect_metric_drift, '_detect_metric_drift')

    # Reduce findings to summaries
    state = _execute_pipeline_stage_with_count(state, reduce, 'reduce', _count_top_findings)

    # Generate recommended actions
    state = _execute_pipeline_stage_with_count(state, actions, 'actions', _count_actions)

    # Process cross-host correlations
    _execute_void_pipeline_stage(state, _process_multi_host_correlations, '_process_multi_host_correlations')

    # Plan follow-up investigations
    _execute_void_pipeline_stage(state, _plan_followups, '_plan_followups')

    # Process follow-up results
    _execute_void_pipeline_stage(state, _process_followup_results, '_process_followup_results')

    # Generate executive summaries
    state = _execute_pipeline_stage(state, summarize, 'summarize')

    # Add external corpus insights
    state = _execute_pipeline_stage(state, _augment_with_corpus_insights, '_augment_with_corpus_insights')

    # Extract final metrics for logging
    metrics = _extract_summarize_metrics(state)
    log_stage('summarize', **metrics)

    return build_output(state, report_path)


# -----------------
# Policy Layer
# -----------------

APPROVED_DEFAULT = ["/bin","/usr/bin","/usr/local/bin","/sbin","/usr/sbin","/opt/trusted"]
SEVERITY_ORDER = ["info","low","medium","high","critical"]

def _load_config_allowlist() -> set[str]:
    """Load allowlist from configuration."""
    paths: set[str] = set()
    try:
        cfg = load_config()
        for p in cfg.paths.policy_allowlist:
            paths.add(p)
    except Exception:
        pass
    return paths


def _load_file_allowlist() -> set[str]:
    """Load allowlist from policy_allowlist.yaml file."""
    paths: set[str] = set()
    allow_file = Path('policy_allowlist.yaml')
    if allow_file.exists():
        try:
            data = yaml.safe_load(allow_file.read_text()) or {}
            for p in (data.get('allow_executables') or []):
                if isinstance(p, str):
                    paths.add(p)
        except Exception as e:
            _log_error('policy_allowlist_load', e)
    return paths


def _load_env_allowlist() -> set[str]:
    """Load allowlist from AGENT_POLICY_ALLOWLIST environment variable."""
    paths: set[str] = set()
    import os as _os
    env_list = _os.environ.get('AGENT_POLICY_ALLOWLIST','')
    for part in env_list.split(':'):
        part = part.strip()
        if part:
            paths.add(part)
    return paths


def _load_policy_allowlist() -> set[str]:
    """Load policy allowlist from multiple sources."""
    paths: set[str] = set()
    
    # Config-based allowlist
    paths.update(_load_config_allowlist())
    
    # File allowlist
    paths.update(_load_file_allowlist())
    
    # Env variable (colon separated)
    paths.update(_load_env_allowlist())
    
    return paths

def _approved_dirs() -> list[str]:
    import os as _os
    env_dirs = _os.environ.get('AGENT_APPROVED_DIRS')
    if env_dirs:
        return [d for d in (p.strip() for p in env_dirs.split(':')) if d]
    return APPROVED_DEFAULT

def _resolve_approved_dirs(approved: list[str]) -> list[str]:
    """Resolve approved directories to absolute canonical paths."""
    approved_real = []
    for d in approved:
        try:
            approved_real.append(str(Path(d).resolve()))
        except Exception:
            approved_real.append(d)
    return approved_real


def _check_executable_approval(exe: str, allow: set[str], approved_real: list[str]) -> bool:
    """Check if executable is approved (allowlisted or in approved directories)."""
    # Already allowlisted
    if exe in allow:
        return True

    try:
        exe_real = str(Path(exe).resolve())
    except Exception:
        exe_real = exe

    # Check if in approved directories
    for d in approved_real:
        try:
            if os.path.commonpath([exe_real, d]) == d:
                return True
        except Exception:
            continue
    return False


def _escalate_finding_severity(finding: Finding, exe: str) -> None:
    """Escalate finding severity for policy violations."""
    try:
        sev_idx = SEVERITY_ORDER.index(finding.severity.lower()) if finding.severity else 0
    except ValueError:
        sev_idx = 0

    target = 'high'
    if finding.severity.lower() != 'critical' and finding.severity.lower() != target:
        # Only raise if below target
        if SEVERITY_ORDER.index(target) > sev_idx:
            old = finding.severity
            finding.severity = target
            finding.severity_source = 'policy'

            rationale_msg = f"policy escalation: executable outside approved dirs ({exe})"
            if finding.rationale:
                finding.rationale.append(rationale_msg)
            else:
                finding.rationale = [rationale_msg]

            if finding.tags is not None:
                if 'policy:denied_path' not in finding.tags:
                    finding.tags.append('policy:denied_path')
                sev_tag = f'severity:{target}'
                if sev_tag not in finding.tags:
                    finding.tags.append(sev_tag)


def _apply_policy_to_finding(finding: Finding, allow: set[str], approved_real: list[str]) -> None:
    """Apply policy enforcement to a single finding."""
    exe = finding.metadata.get('exe') if isinstance(finding.metadata, dict) else None
    if not exe:
        return

    if not _check_executable_approval(exe, allow, approved_real):
        _escalate_finding_severity(finding, exe)

        # risk_subscores impact bump (optional)
        if finding.risk_subscores:
            new_imp = min(10.0, (finding.risk_subscores.get('impact', 0) + 1.0))
            if new_imp != finding.risk_subscores.get('impact'):
                finding.risk_subscores['impact'] = new_imp
                _recompute_finding_risk(finding)


def _process_policy_enforcement(state: AgentState, allow: set[str], approved_real: list[str]) -> None:
    """Process policy enforcement for all findings."""
    if not state.report or not state.report.results:
        return

    for sr in state.report.results:
        for f in sr.findings:
            _apply_policy_to_finding(f, allow, approved_real)


def apply_policy(state: AgentState) -> AgentState:
    """Apply security policies to escalate findings for executables outside approved directories."""
    if not state.report:
        return state

    allow = _load_policy_allowlist()
    approved = _approved_dirs()
    approved_real = _resolve_approved_dirs(approved)

    _process_policy_enforcement(state, allow, approved_real)

    return state