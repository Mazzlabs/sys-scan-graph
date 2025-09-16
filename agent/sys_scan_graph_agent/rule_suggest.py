from __future__ import annotations
import argparse, json
from pathlib import Path
from .rule_gap_miner import mine_gap_candidates, refine_with_llm
from .rule_redundancy import compute_redundancy

# CLI entrypoint to mine gaps, refine, and emit at least one candidate rule.

def suggest_rules(args=None):
    parser = argparse.ArgumentParser('agent rule-suggest')
    parser.add_argument('--input', required=True, help='Path to enriched report JSON (or directory)')
    parser.add_argument('--output', required=False, help='Where to write suggestions JSON (default stdout)')
    parser.add_argument('--min-risk', type=float, default=0.6, help='Minimum risk for candidate findings')
    parser.add_argument('--max-rules', type=int, default=5, help='Maximum number of gap candidate rules')
    parser.add_argument('--redundancy-threshold', type=float, default=0.8, help='Jaccard overlap threshold to treat rules as redundant')
    parser.add_argument('--refine', action='store_true', help='Apply heuristic refinement pass')
    ns = parser.parse_args(args=args)

    in_path = Path(ns.input)
    reports = []
    if in_path.is_dir():
        for p in in_path.glob('*.json'):
            reports.append(p)
    else:
        reports.append(in_path)

    all_data = []
    for p in reports:
        try:
            all_data.append(json.loads(p.read_text()))
        except Exception:
            continue
    # Flatten findings from all reports
    findings = []
    for d in all_data:
        # Accept both enriched_findings (preferred) and plain findings list
        source_list = d.get('enriched_findings') or d.get('findings') or []
        for f in source_list:
            if not isinstance(f, dict):
                continue
            risk_total = f.get('risk_total') or f.get('risk_score') or f.get('risk') or 0
            # Normalize 0-100 risk; ns.min_risk provided 0-1 scale for convenience
            if risk_total >= ns.min_risk * 100:
                findings.append(f)
    # Adapt interface: we write temporary findings into expected structure and reuse miner logic by writing to temp file list
    # Instead of changing miner signature, create in-memory JSON file-like via temp directory.
    import tempfile, json as _json
    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)
        # Group findings into a single synthetic enriched report
        rep_path = tmpdir / 'synthetic.json'
        rep_obj = {'enriched_findings': findings}
        rep_path.write_text(_json.dumps(rep_obj))
        # risk_total is 0-100 scale; our min_risk passed as 0-1, convert.
        gaps_obj = mine_gap_candidates([rep_path], risk_threshold=int(ns.min_risk*100), min_support=2)
        gaps = gaps_obj.get('suggestions', [])
    if ns.refine:
        for g in gaps:
            refine_with_llm(g)

    # Basic redundancy filter on suggested token sets (dedupe near-identical criteria)
    unique = []
    seen_tokens = []
    for g in gaps:
        tokens = tuple(sorted(g.get('tokens', [])))
        if any(len(set(tokens) & set(t)) / max(1,len(set(tokens)|set(t))) >= ns.redundancy_threshold for t in seen_tokens):
            continue
        seen_tokens.append(tokens)
        unique.append(g)
    # Ensure at least one candidate
    if not unique and gaps:
        unique.append(gaps[0])
    # Fallback: if still no candidates but we have multiple high-risk findings, attempt simple prefix clustering
    if not unique and len(findings) >= 2:
        import re
        tok_lists = []
        for f in findings:
            toks = [t.lower() for t in re.findall(r"[A-Za-z0-9_]+", f.get('title','')) if not t.isdigit()]
            tok_lists.append((f, toks))
        # Group by first 4 tokens (or all if shorter)
        from collections import defaultdict
        groups = defaultdict(list)
        for f,toks in tok_lists:
            if not toks: continue
            prefix = tuple(toks[:4])
            groups[prefix].append(f)
        # Pick largest group size >=2
        best = None
        for k,v in groups.items():
            if len(v) >= 2 and (best is None or len(v) > len(best[1])):
                best = (k,v)
        if best:
            prefix_tokens, members = best
            cond_tokens = list(dict.fromkeys(prefix_tokens))[:2]
            conditions = [{'field':'title','contains':t} for t in cond_tokens]
            unique.append({
                'id': 'auto_prefix_cluster',
                'title': f"Auto Suggested: {' '.join(t.capitalize() for t in cond_tokens)}",
                'rationale': f"Clustered {len(members)} similar high-risk findings by shared prefix",
                'conditions': conditions,
                'logic': 'all',
                'risk_score_delta': 5,
                'tags': ['auto_suggested','gap_candidate','prefix_cluster']
            })

    output_obj = {'candidates': unique, 'candidate_count': len(unique)}
    out_json = json.dumps(output_obj, indent=2)
    if ns.output:
        Path(ns.output).write_text(out_json)
    else:
        print(out_json)

if __name__ == '__main__':  # pragma: no cover
    suggest_rules()
