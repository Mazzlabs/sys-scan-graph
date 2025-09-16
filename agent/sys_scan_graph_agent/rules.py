from __future__ import annotations
from typing import List, Dict, Any
from . import models
from collections import defaultdict
import os, json, hashlib, time
try:
    import yaml  # optional; rule dir may use YAML
except ImportError:  # fallback if PyYAML not installed (should be via requirements)
    yaml = None

# Simple deterministic correlation rules (Phase 1)
# Rules operate on already emitted findings (post-scanner)

# ---- Rule cache (Phase 10 optimization) ----
RULE_CACHE: dict[str, dict[str, Any]] = {}
# structure: { path: { 'rules': [...], 'mtimes': {file: mtime}, 'last_load': ts } }
CACHE_TTL = 30  # seconds safety; reload if exceeded even if mtime same (defense against clock skew)

def _collect_rule_files(rules_dir: str) -> list[str]:
    files = []
    try:
        for name in sorted(os.listdir(rules_dir)):
            if name.endswith(('.yml','.yaml','.json')):
                files.append(os.path.join(rules_dir, name))
    except Exception:
        return []
    return files

def _needs_reload(path: str, record: dict[str, Any]) -> bool:
    files = _collect_rule_files(path)
    mtimes_new = {}
    changed = False
    for f in files:
        try:
            mt = os.path.getmtime(f)
            mtimes_new[f] = mt
            if record['mtimes'].get(f) != mt:
                changed = True
        except Exception:
            changed = True
    # Detect deleted files
    for old in list(record['mtimes'].keys()):
        if old not in mtimes_new:
            changed = True
    if not changed and (time.time() - record.get('last_load',0) > CACHE_TTL):
        changed = True
    if changed:
        record['mtimes'] = mtimes_new
    return changed

class Correlator:
    def __init__(self, rules: List[Dict]):
        self.rules = rules

    @staticmethod
    def match_condition(f: models.Finding, cond: Dict) -> bool:
        # cond: {field, contains, equals, metadata_key, metadata_contains}
        field = cond.get("field")
        if field:
            value = getattr(f, field, None)
        else:
            value = f.description or ""
        if value is None:
            return False
        if "contains" in cond and cond["contains"] not in str(value):
            return False
        if "equals" in cond and str(value) != cond["equals"]:
            return False
        meta_key = cond.get("metadata_key")
        if meta_key:
            mv = f.metadata.get(meta_key, "")
            if "metadata_contains" in cond and cond["metadata_contains"] not in mv:
                return False
        return True

    def apply(self, findings: List[models.Finding]) -> List[models.Correlation]:
        correlations: List[models.Correlation] = []
        by_id = {f.id: f for f in findings}
        # Index by tags for multi-finding joins
        tag_index = defaultdict(list)
        for f in findings:
            for t in f.tags:
                tag_index[t].append(f)
        for r in self.rules:
            relevant = []
            hit_map = {}
            logic_any = r.get("logic","all") == "any"
            scope_ids = r.get("finding_ids")  # optional explicit list
            candidate_list = [by_id[i] for i in scope_ids if i in by_id] if scope_ids else findings
            for f in candidate_list:
                conds = r.get("conditions", [])
                if not conds:
                    continue
                satisfied_labels = []
                if logic_any:
                    for idx,c in enumerate(conds):
                        if self.match_condition(f,c):
                            satisfied_labels.append(f"c{idx}:{c.get('field') or c.get('metadata_key') or 'desc'}")
                    if satisfied_labels:
                        relevant.append(f)
                else:
                    all_hit = True
                    for idx,c in enumerate(conds):
                        if self.match_condition(f,c):
                            satisfied_labels.append(f"c{idx}:{c.get('field') or c.get('metadata_key') or 'desc'}")
                        else:
                            all_hit = False
                    if all_hit:
                        relevant.append(f)
                if satisfied_labels:
                    hit_map[f.id] = satisfied_labels
            if relevant:
                # Exposure scoring heuristic: +1 per distinct exposure tag
                exposure_tags = {t for f in relevant for t in f.tags if t in {"listening","suid","network_port"}}
                exposure_bonus = len(exposure_tags)
                base_delta = r.get("risk_score_delta",0)
                corr_id = r.get("id") or f"corr_{len(correlations)+1}"
                correlations.append(models.Correlation(
                    id=corr_id,
                    title=r.get("title","Unnamed Correlation"),
                    rationale=r.get("rationale",""),
                    related_finding_ids=[f.id for f in relevant],
                    risk_score_delta=base_delta + exposure_bonus,
                    tags=r.get("tags",[]),
                    severity=r.get("severity"),
                    predicate_hits=hit_map if hit_map else None
                ))
        return correlations

DEFAULT_RULES = [
    # Single finding heuristic (ip_forward enabled)
    {
        "id":"ip_forward_enabled",
        "title":"IP forwarding enabled",
        "rationale":"Host has net.ipv4.ip_forward=1 which increases lateral routing capability.",
        "conditions":[{"metadata_key":"sysctl_key","equals":"net.ipv4.ip_forward","metadata_contains":"1"}],
        "logic":"all",
        "risk_score_delta":5,
        "tags":["routing","surface"]
    },
    # Multi-finding NAT context: require ip_forward + presence of NAT/bridge module finding(s)
    {
        "id":"nat_context_multi",
        "title":"Potential routing/NAT capability (multi-signal)",
        "rationale":"Combination of ip_forward and NAT/bridge related modules indicates potential NAT/router role.",
        "conditions":[
            {"metadata_key":"sysctl_key","equals":"net.ipv4.ip_forward","metadata_contains":"1"},
            {"field":"title","contains":"module", "equals":""}  # placeholder broad condition; refine with real module signal metadata
        ],
        "logic":"any",  # for now: any condition yields relevance; multi-finding scoring adds exposure bonus
        "risk_score_delta":8,
        "tags":["routing","exposure"]
    }
]

# -------------------------------------------------
# Rule loading / linting / dry-run utilities
# -------------------------------------------------

def load_rules_dir(rules_dir: str) -> List[Dict[str, Any]]:
    if not rules_dir or not os.path.isdir(rules_dir):
        return []
    rec = RULE_CACHE.get(rules_dir)
    if rec is None:
        rec = {'rules': [], 'mtimes': {}, 'last_load': 0}
        RULE_CACHE[rules_dir] = rec
    # Decide reload
    if _needs_reload(rules_dir, rec):
        out: List[Dict[str, Any]] = []
        for path in _collect_rule_files(rules_dir):
            name = os.path.basename(path)
            try:
                with open(path, 'r') as f:
                    if name.endswith('.json'):
                        data = json.load(f)
                    else:
                        if not yaml:
                            continue
                        data = yaml.safe_load(f)
            except Exception:
                continue
            if isinstance(data, dict):
                out.append(data)
            elif isinstance(data, list):
                out.extend([d for d in data if isinstance(d, dict)])
        # Ensure unique ids
        seen = set()
        for r in out:
            if not r.get('id'):
                r['id'] = 'auto_' + hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()[:10]
            if r['id'] in seen:
                r['id'] += '_dup'
            seen.add(r['id'])
        rec['rules'] = out
        rec['last_load'] = time.time()
    return rec['rules']

# Legacy compatibility: existing functions below unchanged except load_rules_dir above

def canonical_condition_signature(rule: Dict[str, Any]) -> str:
    conds = rule.get('conditions') or []
    parts = []
    for c in conds:
        frag = []
        for k in ['field','contains','equals','metadata_key','metadata_contains']:
            if k in c:
                frag.append(f"{k}:{c[k]}")
        parts.append('|'.join(frag))
    parts.sort()
    return '&&'.join(parts) + f"|logic={rule.get('logic','all')}"

def lint_rules(rules: List[Dict[str, Any]]) -> List[Dict[str,str]]:
    issues: List[Dict[str,str]] = []
    id_map = {r.get('id'): r for r in rules if r.get('id')}
    signatures = {}
    for r in rules:
        rid = r.get('id','?')
        sig = canonical_condition_signature(r)
        if sig in signatures:
            issues.append({'rule_id': rid, 'code':'unreachable', 'detail': f'shadowed_by={signatures[sig]}'})
        else:
            signatures[sig] = rid
        # dependency checks
        deps = r.get('requires') or r.get('required_rules') or []
        for d in deps:
            if d not in id_map:
                issues.append({'rule_id': rid, 'code':'missing_dependency', 'detail': d})
        # tag dependency checks
    all_tags = {t for r in rules for t in (r.get('tags') or [])}
    for r in rules:
        req_tags = r.get('requires_tags') or []
        for t in req_tags:
            if t not in all_tags:
                issues.append({'rule_id': r.get('id','?'), 'code':'missing_required_tag', 'detail': t})
    return issues

def dry_run_apply(rules: List[Dict[str, Any]], findings: List[models.Finding]) -> Dict[str,List[str]]:
    result: Dict[str,List[str]] = {}
    for r in rules:
        rid = r.get('id','?')
        corr = Correlator([r])
        corrs = corr.apply(findings)
        matched = []
        for c in corrs:
            matched.extend(c.related_finding_ids)
        result[rid] = sorted(set(matched))
    return result
