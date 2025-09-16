from __future__ import annotations
import json, copy
from pathlib import Path
from typing import Dict, List, Any
from . import models
from . import risk
from . import calibration
EnrichedOutput = models.EnrichedOutput
Finding = models.Finding
compute_risk = risk.compute_risk
load_persistent_weights = risk.load_persistent_weights
apply_probability = calibration.apply_probability


def apply_ip_forward_disabled(f: Finding) -> Finding:
    """Return modified copy of ip_forward kernel_param finding as if disabled."""
    nf = copy.deepcopy(f)
    if nf.metadata is None:
        nf.metadata = {}
    orig_val = nf.metadata.get('value') or nf.metadata.get('desired') or nf.metadata.get('current')
    nf.metadata['counterfactual_original_value'] = orig_val
    nf.metadata['value'] = '0'
    # Reduce impact: treat as normalized benign param
    if nf.risk_subscores and 'impact' in nf.risk_subscores:
        nf.risk_subscores['impact'] = max(0.5, nf.risk_subscores['impact'] * 0.4)
    if nf.risk_subscores and 'exposure' in nf.risk_subscores:
        nf.risk_subscores['exposure'] = max(0.0, nf.risk_subscores['exposure'] - 0.5)
    return nf


def recompute_risk(findings: List[Finding]):
    weights = load_persistent_weights()
    for f in findings:
        if not f.risk_subscores:
            continue
        score, raw = compute_risk(f.risk_subscores, weights)
        f.risk_score = score
        f.risk_total = score
        f.risk_subscores['_raw_weighted_sum'] = raw
        f.probability_actionable = apply_probability(raw)


def what_if(enriched_path: Path, ip_forward_disabled: bool = False) -> Dict[str, Any]:
    data = json.loads(enriched_path.read_text())
    eo = EnrichedOutput.model_validate(data)
    original_map = {f.id: f for f in eo.enriched_findings or []}
    modified: List[Finding] = []
    changed = []
    for f in eo.enriched_findings or []:
        if ip_forward_disabled and f.category == 'kernel_param' and f.metadata.get('sysctl_key') == 'net.ipv4.ip_forward':
            if str(f.metadata.get('value')) in {'1','true','enabled'}:
                nf = apply_ip_forward_disabled(f)
                modified.append(nf)
                changed.append((f, nf))
                continue
        modified.append(copy.deepcopy(f))
    # Recompute risk for modified list
    recompute_risk(modified)
    # Build changed findings delta info
    deltas = []
    for orig, new in changed:
        deltas.append({
            'id': orig.id,
            'original_risk': orig.risk_total,
            'new_risk': new.risk_total,
            'delta': (new.risk_total or 0) - (orig.risk_total or 0)
        })
    # Residual high-risk cluster (ids with risk >= original median high)
    orig_scores = [f.risk_total or f.risk_score or 0 for f in eo.enriched_findings or []]
    if orig_scores:
        threshold = sorted(orig_scores)[max(0, int(0.7*len(orig_scores))-1)]  # 70th percentile approx
    else:
        threshold = 0
    residual_high = [f.id for f in modified if (f.risk_total or 0) >= threshold]
    return {
        'scenario': {'ip_forward_disabled': ip_forward_disabled},
        'changed_findings': deltas,
        'residual_high_risk_ids': residual_high,
        'original_high_threshold': threshold,
        'technique_coverage': (eo.summaries.attack_coverage if eo.summaries and eo.summaries.attack_coverage else None)
    }
