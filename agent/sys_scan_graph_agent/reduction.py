from __future__ import annotations
from typing import List, Dict, Tuple
from collections import Counter
from . import models
from . import redaction
Finding = models.Finding
Reductions = models.Reductions
redact_text = redaction.redact_text

NOTABLE_MODULE_KEYS = {"br_netfilter","xt_MASQUERADE","bridge","iptable_nat","binfmt_misc"}


def _load_rarity() -> Dict[str, float]:
    from pathlib import Path
    import yaml
    path = Path('rarity.yaml')
    if not path.exists():
        return {}
    try:
        
        
        
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        return {}
    out = {}
    for entry in data.get('modules', []):
        m = entry.get('module')
        rs = entry.get('rarity_score')
        if m and isinstance(rs, (int,float)):
            out[m] = float(rs)
    return out

def summarize_modules(findings: List[Finding]) -> Dict:
    mods = [f.metadata.get("module") for f in findings if f.metadata.get("module")]
    if not mods:
        return {}
    rarity_map = _load_rarity()
    total = len(mods)
    notable = [m for m in mods if m in NOTABLE_MODULE_KEYS]
    freq = Counter(mods)
    uncommon = [m for m,c in freq.items() if c==1 and m not in notable][:10]
    # Module families
    families = [f.metadata.get("module_family") for f in findings if f.metadata.get("module_family")]
    fam_freq = Counter([x for x in families if x])
    # Rarity stats
    rarity_present: List[Tuple[str,float]] = [(m, rarity_map[m]) for m in freq.keys() if m in rarity_map]
    rarity_present.sort(key=lambda x: x[1], reverse=True)
    top_rare = rarity_present[:10]
    avg_rarity = round(sum(r for _,r in rarity_present)/len(rarity_present),3) if rarity_present else 0.0
    return {
        "module_count": total,
        "distinct_modules": len(freq),
        "notable_modules": notable,
        "uncommon_modules": uncommon,
        "module_family_counts": fam_freq.most_common(10),
        "avg_rarity_score": avg_rarity,
        "top_rare_modules": top_rare
    }


def summarize_suid(findings: List[Finding]) -> Dict:
    suid = [f for f in findings if f.metadata.get("suid") == "true"]
    if not suid:
        return {}
    unexpected = [f.metadata.get("path") for f in suid if f.metadata.get("expected") != "true"]
    return {
        "suid_total": len(suid),
        "unexpected_suid": unexpected[:15]
    }


def summarize_network(findings: List[Finding]) -> Dict:
    listeners = [f for f in findings if f.metadata.get("state") == "LISTEN"]
    ports = Counter(f.metadata.get("port") for f in listeners if f.metadata.get("port"))
    top = ports.most_common(15)
    # Known org distribution (remote_org metadata set + known_good tag)
    known = [f.metadata.get('remote_org') for f in findings if f.metadata.get('remote_org') and 'known_good' in (f.tags or [])]
    org_counts = Counter(known)
    return {
        "listen_count": len(listeners),
        "top_listen_ports": top,
        "known_org_count": org_counts.most_common(10)
    }


def top_findings(findings: List[Finding], limit=10) -> List[Dict]:
    sorted_f = sorted(findings, key=lambda f: f.risk_score, reverse=True)
    out = []
    for f in sorted_f[:limit]:
        out.append({
            "id": f.id,
            # Apply redaction to title for evaluation / LLM exposure; raw finding retains original
            "title": redact_text(f.title),
            "severity": f.severity,
            "risk_score": f.risk_score,
            "tags": f.tags
        })
    return out


def reduce_all(findings: List[Finding]) -> Reductions:
    tf = top_findings(findings)
    return Reductions(
        module_summary=summarize_modules(findings),
        suid_summary=summarize_suid(findings),
        network_summary=summarize_network(findings),
        top_findings=tf,
        top_risks=tf  # alias for evaluation clarity
    )
