from __future__ import annotations
from . import models
from pathlib import Path
import json, math

IGNORED_FIELDS = {'raw_reference','followups','integrity'}


def _finding_index(out: models.EnrichedOutput):
    idx = {}
    for f in out.enriched_findings or []:
        idx[f.id] = f
    return idx

def risk_bucket(r: float|None):
    if r is None: return 'none'
    if r >= 80: return 'critical'
    if r >= 60: return 'high'
    if r >= 40: return 'medium'
    if r >= 20: return 'low'
    return 'info'

def build_diff(prev: models.EnrichedOutput, curr: models.EnrichedOutput) -> str:
    prev_idx = _finding_index(prev)
    curr_idx = _finding_index(curr)
    added, removed, changed = [], [], []
    for fid, f in curr_idx.items():
        if fid not in prev_idx:
            added.append(f)
        else:
            pf = prev_idx[fid]
            if (pf.risk_total or pf.risk_score) != (f.risk_total or f.risk_score):
                delta = (f.risk_total or f.risk_score or 0) - (pf.risk_total or pf.risk_score or 0)
                changed.append((f, delta))
    for fid, f in prev_idx.items():
        if fid not in curr_idx:
            removed.append(f)
    changed.sort(key=lambda x: abs(x[1]), reverse=True)
    lines = ["# Enriched Report Diff", "", f"Added findings: {len(added)}", f"Removed findings: {len(removed)}", f"Risk changes: {len(changed)}", ""]
    lines.append("## Added (sorted by risk)")
    for f in sorted(added, key=lambda x: x.risk_total or x.risk_score or 0, reverse=True)[:50]:
        lines.append(f"- + [{risk_bucket(f.risk_total or f.risk_score)}] {f.id} {f.title} risk={f.risk_total or f.risk_score}")
    lines.append("\n## Removed")
    for f in sorted(removed, key=lambda x: x.risk_total or x.risk_score or 0, reverse=True)[:50]:
        lines.append(f"- - [{risk_bucket(f.risk_total or f.risk_score)}] {f.id} {f.title} risk={f.risk_total or f.risk_score}")
    lines.append("\n## Risk Movement (top 50 by |delta|)")
    for f, delta in changed[:50]:
        lines.append(f"- Δ {delta:+.1f} [{risk_bucket(f.risk_total or f.risk_score)}] {f.id} {f.title} now={f.risk_total or f.risk_score}")
    # Aggregate probability_actionable delta
    prev_probs = [pf.probability_actionable or 0 for pf in prev.enriched_findings or []]
    curr_probs = [cf.probability_actionable or 0 for cf in curr.enriched_findings or []]
    prev_avg = sum(prev_probs)/len(prev_probs) if prev_probs else 0
    curr_avg = sum(curr_probs)/len(curr_probs) if curr_probs else 0
    lines.append("\n## Probability Actionable Delta")
    lines.append(f"Prev avg: {prev_avg:.3f} Curr avg: {curr_avg:.3f} Δ={curr_avg - prev_avg:+.3f}")
    return '\n'.join(lines) + '\n'

def write_diff(prev: models.EnrichedOutput, curr: models.EnrichedOutput, path: Path):
    text = build_diff(prev, curr)
    path.write_text(text, encoding='utf-8')
    return path
