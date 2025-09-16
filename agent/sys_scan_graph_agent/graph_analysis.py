from __future__ import annotations
"""Correlation graph analysis: builds bipartite graph Finding <-> Correlation.

Outputs:
  - degree centrality (simple degree count) for findings & correlations
  - connected components (clusters) as triage units
  - cluster summaries with risk aggregates
"""
from typing import Dict, List, Set, Tuple
from . import models
AgentState = models.AgentState
Finding = models.Finding
Correlation = models.Correlation

def build_bipartite(state: AgentState) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    """Return adjacency maps:
       f2c: finding_id -> set(correlation_id)
       c2f: correlation_id -> set(finding_id)
    """
    f2c: Dict[str, Set[str]] = {}
    c2f: Dict[str, Set[str]] = {}
    for c in state.correlations:
        for fid in c.related_finding_ids:
            f2c.setdefault(fid, set()).add(c.id)
            c2f.setdefault(c.id, set()).add(fid)
    return f2c, c2f

def connected_components(f2c: Dict[str, Set[str]], c2f: Dict[str, Set[str]]) -> List[Tuple[Set[str], Set[str]]]:
    visited_f: Set[str] = set()
    visited_c: Set[str] = set()
    components: List[Tuple[Set[str], Set[str]]] = []
    for f in f2c.keys():
        if f in visited_f:
            continue
        # BFS/DFS
        stack_f = [f]
        comp_f: Set[str] = set()
        comp_c: Set[str] = set()
        while stack_f:
            cf = stack_f.pop()
            if cf in visited_f:
                continue
            visited_f.add(cf)
            comp_f.add(cf)
            for cid in f2c.get(cf, []):
                if cid not in visited_c:
                    # process correlation
                    visited_c.add(cid)
                    comp_c.add(cid)
                    # add its findings
                    for nf in c2f.get(cid, []):
                        if nf not in visited_f:
                            stack_f.append(nf)
        if comp_f or comp_c:
            components.append((comp_f, comp_c))
    # Add isolated correlations (no findings) if any
    for c in c2f.keys():
        if c not in visited_c:
            components.append((set(), {c}))
    return components

def annotate_and_summarize(state: AgentState) -> Dict:
    if not state.report:
        return {}
    f2c, c2f = build_bipartite(state)
    comps = connected_components(f2c, c2f)
    # Build lookup for findings objects
    fid_to_obj: Dict[str, Finding] = {}
    for sr in state.report.results:
        for finding in sr.findings:
            fid_to_obj[finding.id] = finding
    # Degree centrality & hub marking
    for fid, corr_ids in f2c.items():
        if fid in fid_to_obj:
            fid_to_obj[fid].graph_degree = len(corr_ids)
    # Summaries
    clusters = []
    cluster_id = 1
    for fset, cset in comps:
        total_risk = 0
        max_deg = -1
        hub_fid = None
        for fid in fset:
            fo = fid_to_obj.get(fid)
            if not fo:
                continue
            total_risk += fo.risk_score
            deg = fo.graph_degree or 0
            if deg > max_deg:
                max_deg = deg
                hub_fid = fid
            fo.cluster_id = cluster_id
        clusters.append({
            "cluster_id": cluster_id,
            "finding_count": len(fset),
            "correlation_count": len(cset),
            "finding_ids": sorted(list(fset)),
            "correlation_ids": sorted(list(cset)),
            "total_risk_score": total_risk,
            "hub_finding_id": hub_fid,
            "hub_degree": max_deg if max_deg >=0 else None
        })
        cluster_id += 1
    # Top 5 clusters by total risk
    sorted_clusters = sorted(clusters, key=lambda c: c.get("total_risk_score",0), reverse=True)
    top5 = []
    for c in sorted_clusters[:5]:
        hub_title = None
        if c.get("hub_finding_id") and c["hub_finding_id"] in fid_to_obj:
            hub_title = fid_to_obj[c["hub_finding_id"].__str__()].title if hasattr(fid_to_obj[c["hub_finding_id"]], 'title') else fid_to_obj[c["hub_finding_id"]].title
        top5.append({
            "cluster_id": c["cluster_id"],
            "total_risk_score": c["total_risk_score"],
            "finding_count": c["finding_count"],
            "correlation_count": c["correlation_count"],
            "hub_finding_id": c.get("hub_finding_id"),
            "hub_finding_title": hub_title
        })
    return {
        "finding_degrees": {fid: len(cids) for fid, cids in f2c.items()},
        "clusters": clusters,
        "top_clusters": top5
    }
