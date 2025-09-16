from __future__ import annotations
from pathlib import Path
from . import models
import html, json, datetime

CSS = """
body { font-family: system-ui, sans-serif; margin: 1.2rem; background:#f9fafb; color:#111; }
header { margin-bottom:1rem; }
.badge { display:inline-block; padding:2px 6px; border-radius:4px; font-size:12px; background:#e2e8f0; margin-right:4px; }
.sev-info { background:#e2e8f0; }
.sev-low { background:#cbd5e1; }
.sev-medium { background:#fde68a; }
.sev-high { background:#fca5a5; }
.sev-critical { background:#fb7185; color:#fff; }
.finding { border:1px solid #e2e8f0; border-left:4px solid #94a3b8; background:#fff; padding:.6rem .8rem; margin:.6rem 0; }
.finding.high { border-left-color:#ef4444; }
.finding.medium { border-left-color:#f59e0b; }
.finding.critical { border-left-color:#be123c; }
.summary-block { background:#fff; border:1px solid #e2e8f0; padding:.8rem 1rem; margin:1rem 0; }
pre { background:#1e293b; color:#f1f5f9; padding:.5rem; overflow:auto; }
.table { width:100%; border-collapse:collapse; }
.table th, .table td { text-align:left; padding:4px 6px; border-bottom:1px solid #e2e8f0; font-size:13px; }
small { color:#334155; }
.flex { display:flex; gap:1rem; flex-wrap:wrap; }
.card { flex:1 1 300px; background:#fff; border:1px solid #e2e8f0; padding:.7rem .9rem; }
footer { margin-top:2rem; font-size:12px; color:#64748b; }
"""

def render(output: models.EnrichedOutput) -> str:
    now = datetime.datetime.utcnow().isoformat() + 'Z'
    findings = output.enriched_findings or []
    corrs = output.correlations or []
    metrics = (output.summaries.metrics if output.summaries else {}) or {}
    # Compliance summary table & gaps rendering
    comp = metrics.get('compliance_summary') if isinstance(metrics, dict) else None
    comp_rows = ''
    if comp:
        comp_rows = '<table class="table"><tr><th>Standard</th><th>Passed</th><th>Failed</th><th>N/A</th><th>Total</th><th>Score</th></tr>'
        for std, vals in comp.items():
            passed = vals.get('passed'); failed = vals.get('failed'); na = vals.get('not_applicable') or 0
            total = vals.get('total_controls'); score = vals.get('score')
            comp_rows += f"<tr><td>{html.escape(str(std))}</td><td>{passed}</td><td>{failed}</td><td>{na}</td><td>{total}</td><td>{score}</td></tr>"
        comp_rows += '</table>'
    gaps = metrics.get('compliance_gaps') if isinstance(metrics, dict) else None
    gap_rows = ''
    if gaps:
        gap_rows = '<table class="table"><tr><th>Standard</th><th>Control</th><th>Severity</th><th>Hint</th></tr>'
        for g in gaps[:30]:
            gap_rows += f"<tr><td>{html.escape(str(g.get('standard')))}</td><td>{html.escape(str(g.get('control_id')))}</td><td>{html.escape(str(g.get('severity') or ''))}</td><td>{html.escape(str(g.get('remediation_hint') or ''))}</td></tr>"
        gap_rows += '</table>'
    # Sort findings by risk score (highest to lowest) for better organization
    findings = sorted(findings, key=lambda f: (f.risk_total or f.risk_score or 0), reverse=True)
    rows = []
    for f in findings[:400]:  # safety cap
        sev = (f.severity or 'info').lower()
        tags = ''.join(f'<span class="badge">{html.escape(t)}</span>' for t in (f.tags or [])[:12])
        rationale = ''
        if f.rationale:
            rationale = '<ul>' + ''.join(f'<li>{html.escape(r)}</li>' for r in f.rationale[:6]) + '</ul>'
        # Format probability defensively (older models may not set it)
        if f.probability_actionable is not None:
            prob_fmt = f"{f.probability_actionable:.2f}"
        else:
            prob_fmt = "0.00"
        rows.append(f"<div class='finding {sev}'><strong>{html.escape(f.title or f.id)}</strong> <span class='badge sev-{sev}'>{sev}</span> risk={f.risk_total or f.risk_score} prob={prob_fmt} {tags}{rationale}</div>")
    corr_rows = []
    for c in corrs[:120]:
        corr_rows.append(f"<div class='finding'><strong>{html.escape(c.title)}</strong> <small>{len(c.related_finding_ids)} findings</small><br>{html.escape(c.rationale or '')}</div>")
    exec_summary = html.escape(output.summaries.executive_summary if output.summaries and output.summaries.executive_summary else '(no executive summary)')
    attack = output.summaries.attack_coverage if output.summaries else {}
    attack_html = ''
    if attack:
        attack_html = '<div class="card"><h3>ATT&CK Coverage</h3>' + f"Techniques: {attack.get('technique_count')}<br>" + '</div>'
    return f"""<!DOCTYPE html><html><head><meta charset='utf-8'><title>sys-scan Report</title><style>{CSS}</style></head>
<body><header><h1>sys-scan Enriched Report</h1><small>Generated {now}</small></header>
<section class='summary-block'><h2>Executive Summary</h2><p>{exec_summary}</p></section>
<div class='flex'>
<div class='card'><h3>Metrics</h3><pre>{html.escape(json.dumps(metrics, indent=2)[:4000])}</pre></div>
{attack_html}
<div class='card'><h3>Compliance</h3>{comp_rows if comp_rows else '<small>No compliance data</small>'}</div>
<div class='card'><h3>Correlations</h3><p>{len(corrs)} correlation(s)</p></div>
</div>
{('<section class="summary-block"><h2>Compliance Gaps</h2>' + gap_rows + '</section>') if gap_rows else ''}
<h2>Findings ({len(findings)})</h2>
{''.join(rows)}
<h2>Correlations</h2>
{''.join(corr_rows)}
<footer>Static HTML artifact. No external JS. sys-scan.</footer>
</body></html>"""

def write_html(output: models.EnrichedOutput, path: Path):
    html_str = render(output)
    path.write_text(html_str, encoding='utf-8')
    return path
