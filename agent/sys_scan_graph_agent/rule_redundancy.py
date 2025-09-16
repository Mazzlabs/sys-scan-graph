from __future__ import annotations
import json, time
from pathlib import Path
from typing import List, Dict, Any, Tuple

# Simple redundancy detector: two rule correlations are redundant if Jaccard overlap of matched finding sets >= threshold.

def compute_redundancy(enriched_paths: List[Path], threshold: float = 0.8, window_seconds: int = 30*86400) -> Dict[str,Any]:
    # Accumulate correlation -> finding ids (set)
    now = time.time()
    corr_map: Dict[str,set] = {}
    for p in enriched_paths:
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        # (Optional) could filter by time inside file if ts stored; we skip due to missing
        for c in data.get('correlations', []) or []:
            cid = c.get('id')
            fids = c.get('related_finding_ids') or []
            if not cid or not fids:
                continue
            corr_map.setdefault(cid, set()).update(fids)
    pairs = []
    ids = sorted(corr_map.keys())
    for i in range(len(ids)):
        for j in range(i+1, len(ids)):
            a,b = ids[i], ids[j]
            set_a, set_b = corr_map[a], corr_map[b]
            if not set_a or not set_b:
                continue
            inter = len(set_a & set_b)
            union = len(set_a | set_b)
            if union == 0: continue
            score = inter / union
            if score >= threshold:
                pairs.append({'rule_a': a, 'rule_b': b, 'overlap': score, 'a_count': len(set_a), 'b_count': len(set_b)})
    return {'threshold': threshold, 'redundant_pairs': pairs, 'rule_count': len(ids)}
