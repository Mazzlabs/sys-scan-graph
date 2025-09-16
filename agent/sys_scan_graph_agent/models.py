from __future__ import annotations
from typing import List, Dict, Optional, Any, Union
from pydantic import BaseModel, Field
import hashlib

# -----------------
# Core Report Schema (subset + extensions)
# -----------------

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    # Legacy field name expected throughout enrichment pipeline. The C++ layer now emits
    # base_severity_score instead; ingestion normalizes by copying that value into risk_score
    # (and risk_total) if risk_score is absent. We retain risk_score as required so downstream
    # code need not handle Optional[int].
    risk_score: int
    # Transitional visibility: surface base_severity_score if present in raw report (or if
    # synthesized during normalization) for transparency / future migration to holistic risk.
    base_severity_score: Optional[int] = None
    description: Optional[str] = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    operational_error: bool = False  # if true, represents scanner operational issue, not security signal
    # Extensions
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    risk_subscores: Optional[Dict[str, float]] = None  # impact/exposure/anomaly/confidence
    correlation_refs: List[str] = Field(default_factory=list)
    baseline_status: Optional[str] = None  # new|existing|unknown
    severity_source: Optional[str] = None  # raw|bumped|rule_engine
    allowlist_reason: Optional[str] = None
    probability_actionable: Optional[float] = None  # calibrated probability (0-1)
    graph_degree: Optional[int] = None  # number of correlations referencing this finding
    cluster_id: Optional[int] = None  # correlation graph connected component id
    rationale: Optional[list[str]] = None  # explanations for risk
    risk_total: Optional[int] = None  # duplicate of risk_score as stable name for external consumption
    host_role: Optional[str] = None  # inferred host role classification (workstation|dev_workstation|bastion|lightweight_router|container_host)
    host_role_rationale: Optional[List[str]] = None  # signals used for role classification
    metric_drift: Optional[dict] = None  # when synthetic metric drift finding, carry metrics metadata

    def identity_hash(self) -> str:
        h = hashlib.sha256()
        # Use stable core identity (scanner + id + title) stored externally
        core = f"{self.id}\n{self.title}\n{self.severity}\n"
        h.update(core.encode())
        return h.hexdigest()

class ScannerResult(BaseModel):
    scanner: str
    finding_count: int
    findings: List[Finding]

class Meta(BaseModel):
    hostname: Optional[str] = None
    tool_version: Optional[str] = None
    json_schema_version: Optional[str] = None
    # Extensions
    host_id: Optional[str] = None
    scan_id: Optional[str] = None

class Summary(BaseModel):
    finding_count_total: Optional[int] = None
    finding_count_emitted: Optional[int] = None
    severity_counts: Dict[str, int] = Field(default_factory=dict)

class SummaryExtension(BaseModel):
    total_risk_score: int
    emitted_risk_score: Optional[int] = None

class Report(BaseModel):
    meta: Meta
    summary: Summary
    results: List[ScannerResult]
    collection_warnings: List[dict] = Field(default_factory=list)
    scanner_errors: List[dict] = Field(default_factory=list)
    summary_extension: SummaryExtension

# -----------------
# Correlation / Enrichment Models
# -----------------

class Correlation(BaseModel):
    id: str
    title: str
    rationale: str
    related_finding_ids: List[str]
    risk_score_delta: int = 0
    tags: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    predicate_hits: Optional[dict[str, list[str]]] = None  # finding_id -> list of condition descriptors satisfied

class Reductions(BaseModel):
    module_summary: Optional[dict] = None
    suid_summary: Optional[dict] = None
    network_summary: Optional[dict] = None
    top_findings: List[dict] = Field(default_factory=list)
    # Alias list for evaluation metrics (same content as top_findings) to express "top_risks" semantics
    top_risks: Optional[List[dict]] = None

class MultiHostCorrelation(BaseModel):
    type: str  # e.g., module_propagation
    key: str   # module name
    host_ids: List[str]
    first_seen_recent: bool = True
    rationale: Optional[str] = None

class Summaries(BaseModel):
    executive_summary: Optional[str] = None
    analyst: Optional[dict] = None
    consistency_findings: Optional[list] = None  # output of Prompt A
    triage_summary: Optional[dict] = None        # structured triage output (Prompt B)
    action_narrative: Optional[str] = None       # human narrative of actions (Prompt C)
    metrics: Optional[dict] = None               # token/latency metrics & alerts
    causal_hypotheses: Optional[list[dict]] = None  # experimental speculative root cause hypotheses
    attack_coverage: Optional[dict] = None       # ATT&CK technique coverage summary

class ActionItem(BaseModel):
    priority: int
    action: str
    correlation_refs: List[str] = Field(default_factory=list)

class AgentWarning(BaseModel):
    module: str
    stage: str
    error_type: str
    message: str
    severity: str = "warning"  # warning|error|info
    hint: Optional[str] = None

class FollowupResult(BaseModel):
    finding_id: str
    plan: List[str] = Field(default_factory=list)
    results: dict = Field(default_factory=dict)
    status: str = "executed"  # executed|skipped|error
    notes: Optional[str] = None

class EnrichedOutput(BaseModel):
    version: str = "agent_mvp_1"
    correlations: List[Correlation]
    reductions: dict
    summaries: Summaries
    actions: List[ActionItem]
    raw_reference: Optional[str] = None  # sha256 of original report file
    enriched_findings: Optional[List[Finding]] = None  # flattened findings with subscores
    correlation_graph: Optional[dict] = None  # clusters & metrics
    followups: Optional[List[FollowupResult]] = None
    enrichment_results: Optional[dict] = None  # aggregated follow-up verification outcomes
    multi_host_correlation: Optional[List[MultiHostCorrelation]] = None
    integrity: Optional[dict] = None  # sha256 + signature verification status

class AgentState(BaseModel):
    raw_report: Optional[dict] = None
    report: Optional[Report] = None
    correlations: List[Correlation] = Field(default_factory=list)
    reductions: dict = Field(default_factory=dict)
    summaries: Summaries = Field(default_factory=Summaries)
    actions: List[ActionItem] = Field(default_factory=list)
    followups: List[FollowupResult] = Field(default_factory=list)
    enrichment_results: dict = Field(default_factory=dict)
    multi_host_correlation: List[MultiHostCorrelation] = Field(default_factory=list)
    agent_warnings: List[dict] = Field(default_factory=list)

