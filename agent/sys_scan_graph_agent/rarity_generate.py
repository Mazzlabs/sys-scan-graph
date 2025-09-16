from __future__ import annotations
"""Nightly rarity automation utilities.
Generates rarity.yaml with module rarity_score based on cross-host frequencies.
rarity_score = clamp((1 - percentile_rank) * 2, 0, 2)
Percentile rank computed over distinct host occurrence counts.
A naive signature (sha256 of sorted entries) is appended for tamper-evidence.
"""
from pathlib import Path
import yaml, hashlib, json
from . import baseline
from typing import Dict, List

def compute_percentiles(freqs: Dict[str,int]) -> Dict[str,float]:
    if not freqs:
        return {}
    # Sort ascending by host_count
    counts = sorted(set(freqs.values()))
    n = len(counts)
    def pct(count: int) -> float:
        # rank position (inclusive) / n
        less_equal = sum(1 for c in counts if c <= count)
        return less_equal / n
    return {m: pct(c) for m, c in freqs.items()}

def rarity_scores(freqs: Dict[str,int]) -> Dict[str, float]:
    pct = compute_percentiles(freqs)
    scores = {}
    for mod, pr in pct.items():
        raw = (1 - pr) * 2.0
        scores[mod] = max(0.0, min(2.0, round(raw,3)))
    return scores

def generate(db_path: Path = Path('agent_baseline.db'), out: Path = Path('rarity.yaml')) -> Path:
    store = baseline.BaselineStore(db_path)
    freqs = store.aggregate_module_frequencies()
    scores = rarity_scores(freqs)
    payload: dict = { 'modules': [{'module': m, 'hosts': freqs[m], 'rarity_score': scores[m]} for m in sorted(freqs.keys())] }
    # signature
    h = hashlib.sha256()
    for entry in payload['modules']:
        h.update(f"{entry['module']}:{entry['hosts']}:{entry['rarity_score']}".encode())
    payload['signature'] = h.hexdigest()
    out.write_text(yaml.safe_dump(payload, sort_keys=False))
    return out

if __name__ == '__main__':
    path = generate()
    print(f"Generated rarity file at {path}")
