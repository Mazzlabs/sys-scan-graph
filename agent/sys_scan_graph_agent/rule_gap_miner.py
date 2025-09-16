from __future__ import annotations
import json, re, os, math
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from . import llm
import os

TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

class GapCandidate:
    def __init__(self, key: str):
        self.key = key
        self.count = 0
        self.examples: List[Dict[str,Any]] = []
        self.tokens: Dict[str,int] = {}
        self.metadata_keys: Dict[str,int] = {}
        self.severities: Dict[str,int] = {}

    def add(self, finding: Dict[str,Any]):
        self.count += 1
        title = finding.get('title','')
        for t in set(tok.lower() for tok in TOKEN_RE.findall(title) if len(tok) > 3):
            self.tokens[t] = self.tokens.get(t,0)+1
        meta = finding.get('metadata') or {}
        if isinstance(meta, dict):
            for k,v in meta.items():
                if isinstance(v,(str,int,float)):
                    self.metadata_keys[k] = self.metadata_keys.get(k,0)+1
        sev = finding.get('severity','unknown').lower()
        self.severities[sev] = self.severities.get(sev,0)+1
        if len(self.examples) < 5:
            self.examples.append({k:v for k,v in finding.items() if k in {'id','title','severity','metadata','tags'}})

    def rule_skeleton(self) -> Dict[str,Any]:
        # Pick 1-2 distinctive tokens (highest doc freq but not overly common terms)
        token_items = sorted(self.tokens.items(), key=lambda x: (-x[1], x[0]))
        chosen_tokens = [t for t,_ in token_items[:2]] or [self.key]
        conditions = []
        for tok in chosen_tokens:
            conditions.append({'field':'title','contains':tok})
        # Metadata conditions (only if appear in all examples and scalar simple value)
        meta_always = []
        if self.examples:
            common_keys = set(self.examples[0].get('metadata',{}).keys())
            for ex in self.examples[1:]:
                common_keys &= set((ex.get('metadata') or {}).keys())
            for k in sorted(common_keys):
                vals = { (ex.get('metadata') or {}).get(k) for ex in self.examples }
                if len(vals) == 1:
                    v = list(vals)[0]
                    if isinstance(v,(str,int,float)) and len(str(v)) < 64:
                        meta_always.append({'metadata_key':k,'metadata_contains':str(v)})
        conditions.extend(meta_always[:2])
        rid = f"gap_{self.key[:40]}"
        title_tokens = ' '.join(t.capitalize() for t in chosen_tokens[:3])
        return {
            'id': rid,
            'title': f"Auto Suggested: {title_tokens}",
            'rationale': f"Suggested from {self.count} recurring uncorrrelated high-risk findings",
            'conditions': conditions,
            'logic': 'all',
            'risk_score_delta': 5,
            'tags': ['auto_suggested','gap_candidate']
        }


def normalize_title(title: str) -> str:
    # Remove digits/paths, keep tokens
    tokens = [t.lower() for t in TOKEN_RE.findall(title) if not t.isdigit()]
    if not tokens:
        return 'untitled'
    return '_'.join(tokens[:6])


def mine_gap_candidates(paths: List[Path], risk_threshold: int = 60, min_support: int = 3) -> Dict[str,Any]:
    candidates: Dict[str, GapCandidate] = {}
    for p in paths:
        try:
            data = json.loads(p.read_text())
        except Exception:
            continue
        findings = data.get('enriched_findings') or []
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            sev = f.get('severity','').lower()
            risk = f.get('risk_total') or f.get('risk_score') or 0
            # skip if correlated
            if f.get('correlation_refs'):
                continue
            # treat high severity or risk threshold as candidate
            if sev not in {'high','critical'} and risk < risk_threshold:
                continue
            # Skip if any existing rule tag present
            tags = [t for t in f.get('tags') or [] if isinstance(t,str)]
            if any(t.startswith('rule:') for t in tags):
                continue
            key = normalize_title(f.get('title',''))
            cand = candidates.get(key)
            if not cand:
                cand = GapCandidate(key)
                candidates[key] = cand
            cand.add(f)
    # Filter support
    selected = [c for c in candidates.values() if c.count >= min_support]
    selected.sort(key=lambda c: c.count, reverse=True)
    suggestions = [c.rule_skeleton() for c in selected]
    return {
        'total_candidates': len(candidates),
        'selected': len(selected),
        'suggestions': suggestions,
        'candidates': [ {'key':c.key,'count':c.count,'example_titles':[e['title'] for e in c.examples]} for c in selected ]
    }


def refine_with_llm(suggestions: List[Dict[str,Any]], examples: Optional[Dict[str,List[str]]] = None) -> List[Dict[str,Any]]:
    """Augment rule skeletons with improved rationale & token refinement using LLMClient heuristics.
    Since we lack an external LLM call here, leverage deterministic heuristics:
      - Concatenate example titles and extract most common tokens not already in conditions.
      - Expand rationale with token list.
      - Add 'refined' tag.
    """
    client = llm.LLMClient()  # placeholder (not actually used for generation now)
    refined = []
    for s in suggestions:
        rid_val = s.get('id') or ''
        ex_titles = examples.get(rid_val, []) if examples else []
        token_freq: Dict[str,int] = {}
        for t in ex_titles:
            for tok in TOKEN_RE.findall(t.lower()):
                if len(tok) < 4: continue
                token_freq[tok] = token_freq.get(tok,0)+1
        existing_tokens = {c.get('contains') for c in (s.get('conditions') or []) if 'contains' in c}
        extra = [tok for tok,_ in sorted(token_freq.items(), key=lambda x:(-x[1], x[0])) if tok not in existing_tokens][:3]
        if extra:
            # Add one additional condition (any logic) if not duplicate
            for e in extra:
                s.setdefault('conditions', []).append({'field':'title','contains':e})
            # Switch logic to any if multiple condition families present
            if len(s['conditions']) > 3:
                s['logic'] = 'any'
        rationale = s.get('rationale','')
        if extra:
            s['rationale'] = rationale + f" | refined tokens: {', '.join(extra)}"
        tags = s.get('tags',[])
        if 'refined' not in tags:
            tags.append('refined')
        s['tags'] = tags
        refined.append(s)
    # Optional secondary LLM refinement layer (real model integration stub)
    if os.environ.get('AGENT_RULE_REFINER_USE_LLM') == '1':
        try:
            import rule_refiner
            refined = rule_refiner.llm_refine(refined, examples or {})
        except Exception:
            pass
    return refined

