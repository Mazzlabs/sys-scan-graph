from __future__ import annotations
import models
import redaction
import llm_models
from typing import List
import textwrap, json

class LLMClient:
    def __init__(self):
        # Moving averages (simple exponential smoothing placeholders)
        self.avg_prompt_tokens = 0.0
        self.avg_completion_tokens = 0.0
        self.alpha = 0.3

    def _update_avgs(self, pt: int, ct: int):
        if self.avg_prompt_tokens == 0:
            self.avg_prompt_tokens = pt
            self.avg_completion_tokens = ct
        else:
            self.avg_prompt_tokens = self.alpha*pt + (1-self.alpha)*self.avg_prompt_tokens
            self.avg_completion_tokens = self.alpha*ct + (1-self.alpha)*self.avg_completion_tokens
        return self.avg_prompt_tokens, self.avg_completion_tokens
    def _prompt_a_consistency(self, reductions: models.Reductions, correlations: List[models.Correlation]) -> llm_models.PromptAOutput:
        ms = reductions.module_summary or {}
        issues: List[llm_models.ConsistencyIssue] = []
        mc = ms.get('module_count')
        distinct = ms.get('distinct_modules') or mc
        if mc and distinct and mc < distinct:
            issues.append(llm_models.ConsistencyIssue(issue="module_count_lt_distinct", details={"module_count": mc, "distinct": distinct}))
        for c in correlations:
            if not c.related_finding_ids:
                issues.append(llm_models.ConsistencyIssue(issue="empty_correlation", details={"id": c.id}))
        return llm_models.PromptAOutput(findings=issues)

    def _prompt_b_triage(self, reductions: models.Reductions, correlations: List[models.Correlation]) -> llm_models.PromptBOutput:
        top = []
        for f in reductions.top_findings[:5]:
            try:
                top.append(llm_models.TriageFinding(**f))
            except Exception:
                continue
        return llm_models.PromptBOutput(top_findings=top, correlation_count=len(correlations))

    def _prompt_c_actions(self, actions: List[models.ActionItem]) -> llm_models.PromptCOutput:
        lines = []
        for a in actions:
            refs = f" (corr {', '.join(a.correlation_refs)})" if a.correlation_refs else ""
            lines.append(f"{a.priority}. {a.action}{refs}")
        narrative = "\n".join(lines)
        return llm_models.PromptCOutput(action_lines=lines, narrative=narrative)

    def _validate_or_retry(self, builder_fn, max_retries=1):
        # Temperature fixed at 0, tokens bounded externally (placeholder comment)
        attempt = 0
        last_err = None
        while attempt <= max_retries:
            try:
                return builder_fn()
            except Exception as e:
                last_err = e
                attempt += 1
        raise llm_models.GuardrailError(f"Validation failed after {max_retries+1} attempts: {last_err}")

    def summarize(self, reductions: models.Reductions, correlations: List[models.Correlation], actions: List[models.ActionItem],
                  skip: bool = False, previous: models.Summaries | None = None, skip_reason: str | None = None) -> models.Summaries:
        # Prompt B builds on reduced facts
        import time
        start = time.time()
        if skip and previous:
            # Reuse previous summary, annotate note
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
            return reused
        # Redact sensitive fields prior to prompt construction
        try:
            red_red = redaction.redact_reductions(reductions)
        except Exception:
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
        analyst = {"correlation_count": len(correlations), "top_findings_count": len(red_red.top_findings)}
        consistency_obj = self._validate_or_retry(lambda: self._prompt_a_consistency(red_red, correlations))
        triage_obj = self._validate_or_retry(lambda: self._prompt_b_triage(red_red, correlations))
        action_obj = self._validate_or_retry(lambda: self._prompt_c_actions(actions))
        elapsed = int((time.time()-start)*1000)
        # Simulated token counts (deterministic approximation)
        prompt_tokens = 50 + len(lines)*10
        completion_tokens = 40 + len(red_red.top_findings)*8
        avg_pt, avg_ct = self._update_avgs(prompt_tokens, completion_tokens)
        drift_flag = (prompt_tokens > 1.3*avg_pt)
        metrics = {
            'tokens_prompt': prompt_tokens,
            'tokens_completion': completion_tokens,
            'findings_count': len(red_red.top_findings),
            'latency_ms': elapsed,
            'avg_prompt_tokens': round(avg_pt,2),
            'avg_completion_tokens': round(avg_ct,2),
            'budget_alert': drift_flag
        }
        return models.Summaries(
            executive_summary=executive,
            analyst=analyst,
            consistency_findings=[i.model_dump() for i in consistency_obj.findings],
            triage_summary={"top_findings": [tf.model_dump() for tf in triage_obj.top_findings], "correlation_count": triage_obj.correlation_count},
            action_narrative=action_obj.narrative,
            metrics=metrics
        )

