from __future__ import annotations
"""LLM Provider Abstraction (INT-ARCH-001)

Defines a stable interface (ILLMProvider) decoupling the agent pipeline from
any concrete LLM / heuristic implementation. The current NullLLMProvider
implements deterministic, local heuristics only (no external calls) and
reproduces existing summarize / rule refinement behaviour.

Future real models can implement this interface and be injected through
`set_llm_provider` or an environment-driven factory.
"""
from typing import Protocol, List, Optional, Dict, Any, Tuple, NamedTuple
import re, os, time
from datetime import datetime
from . import models
from . import llm_models
from . import redaction
Reductions = models.Reductions
Correlation = models.Correlation
Summaries = models.Summaries
ActionItem = models.ActionItem
PromptAOutput = llm_models.PromptAOutput
PromptBOutput = llm_models.PromptBOutput
PromptCOutput = llm_models.PromptCOutput
ConsistencyIssue = llm_models.ConsistencyIssue
GuardrailError = llm_models.GuardrailError
TriageFinding = llm_models.TriageFinding
redact_reductions = redaction.redact_reductions


class ProviderMetadata(NamedTuple):
    """Structured metadata returned by LLM providers."""
    model_name: str
    provider_name: str
    latency_ms: int
    tokens_prompt: int
    tokens_completion: int
    cached: bool = False
    fallback: bool = False
    error_message: Optional[str] = None
    retry_count: int = 0
    cost_estimate: Optional[float] = None
    temperature: Optional[float] = None
    timestamp: Optional[str] = None


class ILLMProvider(Protocol):
    """Stable LLM abstraction with comprehensive telemetry.

    All methods must be pure / deterministic w.r.t provided arguments unless
    a true stochastic model is injected (in which case upstream caching /
    versioning should account for that).

    Each method returns a tuple of (result, metadata) where metadata contains
    structured telemetry information.
    """

    def summarize(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem], *,
                  skip: bool = False, previous: Optional[Summaries] = None,
                  skip_reason: Optional[str] = None, baseline_context: Optional[Dict[str, Any]] = None) -> Tuple[Summaries, ProviderMetadata]: ...

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], ProviderMetadata]: ...

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]: ...


TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


class NullLLMProvider:
    """Deterministic heuristic implementation (no external inference).

    Mirrors the previous LLMClient behaviour while conforming to ILLMProvider.
    """

    def __init__(self):
        self.avg_prompt_tokens = 0.0
        self.avg_completion_tokens = 0.0
        self.alpha = 0.3

    # ----------------- internal helpers -----------------
    def _update_avgs(self, pt: int, ct: int):
        if self.avg_prompt_tokens == 0:
            self.avg_prompt_tokens = pt
            self.avg_completion_tokens = ct
        else:
            self.avg_prompt_tokens = self.alpha * pt + (1 - self.alpha) * self.avg_prompt_tokens
            self.avg_completion_tokens = self.alpha * ct + (1 - self.alpha) * self.avg_completion_tokens
        return self.avg_prompt_tokens, self.avg_completion_tokens

    def _prompt_a_consistency(self, reductions: Reductions, correlations: List[Correlation]) -> PromptAOutput:
        ms = reductions.module_summary or {}
        issues: List[ConsistencyIssue] = []
        mc = ms.get('module_count')
        distinct = ms.get('distinct_modules') or mc
        if mc and distinct and mc < distinct:
            issues.append(ConsistencyIssue(issue="module_count_lt_distinct", details={"module_count": mc, "distinct": distinct}))
        for c in correlations:
            if not c.related_finding_ids:
                issues.append(ConsistencyIssue(issue="empty_correlation", details={"id": c.id}))
        return PromptAOutput(findings=issues)

    def _prompt_b_triage(self, reductions: Reductions, correlations: List[Correlation]) -> PromptBOutput:
        top = []
        for f in reductions.top_findings[:5]:
            try:
                top.append(TriageFinding(**f))
            except Exception:
                continue
        return PromptBOutput(top_findings=top, correlation_count=len(correlations))

    def _prompt_c_actions(self, actions: List[ActionItem]) -> PromptCOutput:
        lines = []
        for a in actions:
            refs = f" (corr {', '.join(a.correlation_refs)})" if a.correlation_refs else ""
            lines.append(f"{a.priority}. {a.action}{refs}")
        narrative = "\n".join(lines)
        return PromptCOutput(action_lines=lines, narrative=narrative)

    def _validate_or_retry(self, builder_fn, max_retries=1):
        attempt = 0
        last_err = None
        while attempt <= max_retries:
            try:
                return builder_fn()
            except Exception as e:  # pragma: no cover - defensive
                last_err = e
                attempt += 1
        raise GuardrailError(f"Validation failed after {max_retries + 1} attempts: {last_err}")

    # ----------------- interface implementations -----------------
    def summarize(self, reductions: Reductions, correlations: List[Correlation], actions: List[ActionItem], *,
                  skip: bool = False, previous: Optional[Summaries] = None,
                  skip_reason: Optional[str] = None, baseline_context: Optional[Dict[str, Any]] = None) -> Tuple[Summaries, ProviderMetadata]:
        start = time.time()
        if skip and previous:
            reused = previous.model_copy(deep=True)
            note = "No material change: reused previous summary"
            reused.executive_summary = f"{reused.executive_summary} | {note}" if reused.executive_summary else note
            metrics = {
                'tokens_prompt': 0,
                'tokens_completion': 0,
                'findings_count': len(reductions.top_findings),
                'latency_ms': 0,
                'skipped': True,
                'skip_reason': skip_reason or 'low_change'
            }
            reused.metrics = (reused.metrics or {}) | metrics

            metadata = ProviderMetadata(
                model_name="null-heuristic",
                provider_name="null",
                latency_ms=0,
                tokens_prompt=0,
                tokens_completion=0,
                cached=True,
                fallback=False,
                timestamp=datetime.now().isoformat()
            )
            return reused, metadata

        try:
            red_red = redact_reductions(reductions)
        except Exception:  # pragma: no cover - fallback
            red_red = reductions
        lines = []
        if red_red.module_summary:
            lines.append(f"Modules: {red_red.module_summary.get('module_count')} total; notable: {', '.join(red_red.module_summary.get('notable_modules', []))}")
        if red_red.suid_summary:
            lines.append(f"SUID unexpected: {len(red_red.suid_summary.get('unexpected_suid', []))}")
        if red_red.network_summary:
            lines.append(f"Listening ports: {red_red.network_summary.get('listen_count')}")
        if correlations:
            lines.append(f"Correlations: {len(correlations)}")
        executive = "; ".join(lines)[:600]
        if baseline_context:
            executive = (executive + f" | baseline: {len(baseline_context)} lookups") if executive else f"Baseline lookups: {len(baseline_context)}"
        analyst = {"correlation_count": len(correlations), "top_findings_count": len(red_red.top_findings)}
        consistency_obj = self._validate_or_retry(lambda: self._prompt_a_consistency(red_red, correlations))
        triage_obj = self._validate_or_retry(lambda: self._prompt_b_triage(red_red, correlations))
        action_obj = self._validate_or_retry(lambda: self._prompt_c_actions(actions))
        elapsed = int((time.time() - start) * 1000)
        prompt_tokens = 50 + len(lines) * 10
        completion_tokens = 40 + len(red_red.top_findings) * 8
        avg_pt, avg_ct = self._update_avgs(prompt_tokens, completion_tokens)
        drift_flag = (prompt_tokens > 1.3 * avg_pt)
        # Token accounting (abstract for future pricing)
        metrics = {
            'tokens_prompt': prompt_tokens,
            'tokens_completion': completion_tokens,
            'findings_count': len(red_red.top_findings),
            'latency_ms': elapsed,
            'avg_prompt_tokens': round(avg_pt, 2),
            'avg_completion_tokens': round(avg_ct, 2),
            'budget_alert': drift_flag
        }
        summaries = Summaries(
            executive_summary=executive,
            analyst=analyst,
            consistency_findings=[i.model_dump() for i in consistency_obj.findings],
            triage_summary={"top_findings": [tf.model_dump() for tf in triage_obj.top_findings], "correlation_count": triage_obj.correlation_count},
            action_narrative=action_obj.narrative,
            metrics=metrics
        )

        metadata = ProviderMetadata(
            model_name="null-heuristic",
            provider_name="null",
            latency_ms=elapsed,
            tokens_prompt=prompt_tokens,
            tokens_completion=completion_tokens,
            cached=False,
            fallback=False,
            timestamp=datetime.now().isoformat()
        )

        return summaries, metadata

    def triage(self, reductions: Reductions, correlations: List[Correlation]) -> Tuple[Dict[str, Any], ProviderMetadata]:
        start_time = time.time()
        
        triage_obj = self._prompt_b_triage(reductions, correlations)
        result = {
            "top_findings": [tf.model_dump() for tf in triage_obj.top_findings],
            "correlation_count": triage_obj.correlation_count
        }
        
        latency = time.time() - start_time
        metadata = ProviderMetadata(
            model_name="null-heuristic",
            provider_name="null",
            latency_ms=int(latency * 1000),
            tokens_prompt=0,
            tokens_completion=0,
            cached=False,
            fallback=False,
            timestamp=datetime.now().isoformat()
        )
        
        return result, metadata

    def refine_rules(self, suggestions: List[Dict[str, Any]],
                     examples: Optional[Dict[str, List[str]]] = None) -> Tuple[List[Dict[str, Any]], ProviderMetadata]:
        """Heuristic rule refinement (ported from rule_gap_miner.refine_with_llm)."""
        start_time = time.time()
        
        refined = []
        for s in suggestions:
            rid_val = s.get('id') or ''
            ex_titles = examples.get(rid_val, []) if examples else []
            token_freq: Dict[str, int] = {}
            for t in ex_titles:
                for tok in TOKEN_RE.findall(t.lower()):
                    if len(tok) < 4:
                        continue
                    token_freq[tok] = token_freq.get(tok, 0) + 1
            existing_tokens = {c.get('contains') for c in (s.get('conditions') or []) if isinstance(c, dict) and 'contains' in c}
            extra = [tok for tok, _ in sorted(token_freq.items(), key=lambda x: (-x[1], x[0])) if tok not in existing_tokens][:3]
            if extra:
                for e in extra:
                    s.setdefault('conditions', []).append({'field': 'title', 'contains': e})
                if len(s['conditions']) > 3:
                    s['logic'] = 'any'
            rationale = s.get('rationale', '')
            if extra:
                s['rationale'] = rationale + f" | refined tokens: {', '.join(extra)}"
            tags = s.get('tags', [])
            if 'refined' not in tags:
                tags.append('refined')
            s['tags'] = tags
            refined.append(s)
        # Optional secondary LLM refinement layer (delegated to rule_refiner)
        if os.environ.get('AGENT_RULE_REFINER_USE_LLM') == '1':  # pragma: no cover - optional path
            try:
                import rule_refiner
                refined = rule_refiner.llm_refine(refined, examples or {})
            except Exception:
                pass
        
        latency = time.time() - start_time
        metadata = ProviderMetadata(
            model_name="null-heuristic",
            provider_name="null",
            latency_ms=int(latency * 1000),
            tokens_prompt=0,
            tokens_completion=0,
            cached=False,
            fallback=False,
            timestamp=datetime.now().isoformat()
        )
        
        return refined, metadata


# ----------------- Provider registry / injection -----------------
_PROVIDER: ILLMProvider = NullLLMProvider()

def _maybe_init_from_env():  # lazy to avoid hard deps unless requested
    global _PROVIDER
    prov = os.environ.get('AGENT_LLM_PROVIDER','null').lower()
    if prov in {'langchain','openai','lc'}:
        try:
            from providers.langchain_provider import LangChainLLMProvider
            _PROVIDER = LangChainLLMProvider()
        except Exception:
            _PROVIDER = NullLLMProvider()



def get_llm_provider() -> ILLMProvider:
    # Ensure env-based init performed once
    if isinstance(_PROVIDER, NullLLMProvider):
        # Attempt upgrade if env requests
        _maybe_init_from_env()
    return _PROVIDER


def set_llm_provider(provider: ILLMProvider) -> None:
    global _PROVIDER
    _PROVIDER = provider


__all__ = [
    'ILLMProvider', 'NullLLMProvider', 'get_llm_provider', 'set_llm_provider'
]
