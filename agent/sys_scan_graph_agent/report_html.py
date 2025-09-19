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
    
    # Group findings by severity for detailed analysis sections
    severity_groups = {
        'critical': [f for f in findings if (f.severity or '').lower() == 'critical'],
        'high': [f for f in findings if (f.severity or '').lower() == 'high'],
        'medium': [f for f in findings if (f.severity or '').lower() == 'medium'],
        'low': [f for f in findings if (f.severity or '').lower() == 'low']
    }
    
    # Generate detailed risk analysis sections
    risk_analysis_sections = []
    
    # Critical Risk Analysis
    if severity_groups['critical']:
        critical_count = len(severity_groups['critical'])
        critical_analysis = f"""
        <section class='summary-block'>
        <h2>🔴 Critical Risk Analysis ({critical_count} findings)</h2>
        <h3>Risk Assessment</h3>
        <p><strong>Impact:</strong> Critical findings represent immediate security threats that require urgent attention. These issues have the highest potential to compromise system integrity, confidentiality, or availability.</p>
        <p><strong>Business Impact:</strong> These vulnerabilities could lead to complete system compromise, data breaches, or operational disruption. Immediate remediation is essential.</p>
        <h3>Key Findings</h3>
        <ul>
        """
        for f in severity_groups['critical'][:5]:  # Show top 5 critical findings
            desc = f.description or f.title or 'No description available'
            rationale = f'SECURITY ISSUE: {desc}'
            
            # Add specific technical details based on finding type
            if 'deleted_executable' in str(f.metadata):
                rationale += '. This process is running with a deleted executable file, which is a strong indicator of malware or compromise. Attackers often delete their malware binaries after execution to evade detection, but the process continues running.'
            elif 'world_writable_executable' in str(f.metadata):
                rationale += '. This executable has world-writable permissions, allowing any user to modify it. This creates a persistence mechanism where attackers can replace legitimate binaries with malicious ones.'
            elif 'pattern_match' in str(f.metadata):
                rationale += '. This process matches known suspicious patterns that are commonly associated with malicious activity or unauthorized system access.'
            
            tags_str = ', '.join(f.tags or [])
            risk_breakdown = f.risk_subscores
            risk_details = ''
            if risk_breakdown:
                risk_details = f"<br><small>Risk factors - Impact: {risk_breakdown.get('impact', 'N/A')}, Exposure: {risk_breakdown.get('exposure', 'N/A')}, Anomaly: {risk_breakdown.get('anomaly', 'N/A')}, Confidence: {risk_breakdown.get('confidence', 'N/A')}</small>"
            
            critical_analysis += f"<li><strong>{html.escape(f.id)}</strong><br><em>{html.escape(rationale)}</em>{risk_details}<br><small>Risk Score: {f.risk_total or f.risk_score}, Tags: {tags_str}, Baseline: {f.baseline_status or 'unknown'}</small></li>"
        critical_analysis += f"""
        </ul>
        <h3>Recommended Actions</h3>
        <ol>
        <li>Immediate isolation of affected systems</li>
        <li>Emergency patching or mitigation within 24 hours</li>
        <li>Incident response team activation</li>
        <li>Root cause analysis to prevent recurrence</li>
        </ol>
        </section>
        """
        risk_analysis_sections.append(critical_analysis)
    
    # High Risk Analysis
    if severity_groups['high']:
        high_count = len(severity_groups['high'])
        high_analysis = f"""
        <section class='summary-block'>
        <h2>🟠 High Risk Analysis ({high_count} findings)</h2>
        <h3>Risk Assessment</h3>
        <p><strong>Impact:</strong> High-risk findings indicate significant security weaknesses that could be exploited by determined attackers. These require prompt attention to prevent potential breaches.</p>
        <p><strong>Business Impact:</strong> Exploitation could result in unauthorized access, data exposure, or service disruption. These should be addressed within the current sprint or maintenance window.</p>
        <h3>Key Findings</h3>
        <ul>
        """
        for f in severity_groups['high'][:5]:  # Show top 5 high findings
            desc = f.description or f.title or 'No description available'
            rationale = f'SECURITY ISSUE: {desc}'
            
            # Add specific technical details based on finding type
            if 'deleted_executable' in str(f.metadata):
                rationale += '. This process is running with a deleted executable file, which is a strong indicator of malware or compromise. Attackers often delete their malware binaries after execution to evade detection, but the process continues running.'
            elif 'world_writable_executable' in str(f.metadata):
                rationale += '. This executable has world-writable permissions, allowing any user to modify it. This creates a persistence mechanism where attackers can replace legitimate binaries with malicious ones.'
            elif 'pattern_match' in str(f.metadata):
                rationale += '. This process matches known suspicious patterns that are commonly associated with malicious activity or unauthorized system access.'
            
            tags_str = ', '.join(f.tags or [])
            risk_breakdown = f.risk_subscores
            risk_details = ''
            if risk_breakdown:
                risk_details = f"<br><small>Risk factors - Impact: {risk_breakdown.get('impact', 'N/A')}, Exposure: {risk_breakdown.get('exposure', 'N/A')}, Anomaly: {risk_breakdown.get('anomaly', 'N/A')}, Confidence: {risk_breakdown.get('confidence', 'N/A')}</small>"
            
            high_analysis += f"<li><strong>{html.escape(f.id)}</strong><br><em>{html.escape(rationale)}</em>{risk_details}<br><small>Risk Score: {f.risk_total or f.risk_score}, Tags: {tags_str}, Baseline: {f.baseline_status or 'unknown'}</small></li>"
        high_analysis += f"""
        </ul>
        <h3>Recommended Actions</h3>
        <ol>
        <li>Priority remediation within 1-2 weeks</li>
        <li>Implementation of compensating controls if immediate patching isn't feasible</li>
        <li>Enhanced monitoring of affected systems</li>
        <li>Security team review and approval</li>
        </ol>
        </section>
        """
        risk_analysis_sections.append(high_analysis)
    
    # Medium Risk Analysis
    if severity_groups['medium']:
        medium_count = len(severity_groups['medium'])
        medium_analysis = f"""
        <section class='summary-block'>
        <h2>🟡 Medium Risk Analysis ({medium_count} findings)</h2>
        <h3>Risk Assessment</h3>
        <p><strong>Impact:</strong> Medium-risk findings represent moderate security concerns that could be exploited under specific conditions. These should be tracked and remediated as part of regular maintenance.</p>
        <p><strong>Business Impact:</strong> While not immediately critical, these issues could become significant if combined with other vulnerabilities or if attacker sophistication increases.</p>
        <h3>Key Findings</h3>
        <ul>
        """
        for f in severity_groups['medium'][:8]:  # Show top 8 medium findings
            desc = f.description or f.title or 'No description available'
            rationale = f'SECURITY ISSUE: {desc}'
            
            # Add specific technical details based on finding type
            if 'file_capability' in str(f.metadata) or 'capabilities' in desc.lower():
                rationale += '. File capabilities allow binaries to perform privileged operations without full root access. This can be exploited if the binary is compromised, granting attackers elevated privileges for specific system functions.'
            elif 'suid' in str(f.tags) or 'sgid' in str(f.tags):
                rationale += '. SUID/SGID binaries run with elevated privileges of the file owner/group. While necessary for some system functions, they create privilege escalation risks if the binary contains vulnerabilities or can be modified.'
            elif 'world-writable' in desc.lower() or 'world_writable' in str(f.id):
                rationale += '. World-writable files can be modified by any user on the system. This allows attackers to inject malicious content, replace legitimate files, or create backdoors for persistent access.'
            elif 'apparmor' in desc.lower():
                rationale += '. AppArmor provides mandatory access control but has unconfined processes. This reduces the effectiveness of the security framework and may allow unauthorized system access.'
            
            tags_str = ', '.join(f.tags or [])
            risk_breakdown = f.risk_subscores
            risk_details = ''
            if risk_breakdown:
                risk_details = f"<br><small>Risk factors - Impact: {risk_breakdown.get('impact', 'N/A')}, Exposure: {risk_breakdown.get('exposure', 'N/A')}, Anomaly: {risk_breakdown.get('anomaly', 'N/A')}, Confidence: {risk_breakdown.get('confidence', 'N/A')}</small>"
            
            medium_analysis += f"<li><strong>{html.escape(f.id)}</strong><br><em>{html.escape(rationale)}</em>{risk_details}<br><small>Risk Score: {f.risk_total or f.risk_score}, Tags: {tags_str}, Baseline: {f.baseline_status or 'unknown'}</small></li>"
        medium_analysis += f"""
        </ul>
        <h3>Recommended Actions</h3>
        <ol>
        <li>Plan remediation in upcoming maintenance windows</li>
        <li>Document risk acceptance if mitigation is deferred</li>
        <li>Regular monitoring and reassessment</li>
        <li>Consider automation for similar issues</li>
        </ol>
        </section>
        """
        risk_analysis_sections.append(medium_analysis)
    
    # Low Risk Analysis
    if severity_groups['low']:
        low_count = len(severity_groups['low'])
        low_analysis = f"""
        <section class='summary-block'>
        <h2>🟢 Low Risk Analysis ({low_count} findings)</h2>
        <h3>Risk Assessment</h3>
        <p><strong>Impact:</strong> Low-risk findings indicate minor security weaknesses or configuration issues that pose minimal threat under normal circumstances.</p>
        <p><strong>Business Impact:</strong> These issues have limited potential for exploitation and typically don't require immediate action unless they represent systemic problems.</p>
        <h3>Key Findings</h3>
        <ul>
        """
        for f in severity_groups['low'][:10]:  # Show top 10 low findings
            desc = f.description or f.title or 'No description available'
            rationale = f'SECURITY ISSUE: {desc}'
            
            # Add specific technical details based on finding type
            if 'rp_filter' in str(f.id):
                rationale += '. Reverse path filtering is disabled or misconfigured. This network security feature helps prevent IP spoofing attacks but may be intentionally disabled for legitimate networking needs.'
            elif 'suid' in str(f.tags) or 'sgid' in str(f.tags):
                rationale += '. SUID/SGID binaries run with elevated privileges. While often necessary for system operations, they represent potential privilege escalation vectors if exploited.'
            elif 'selinux' in desc.lower():
                rationale += '. SELinux is not enabled. This mandatory access control system provides significant security benefits when properly configured and enforced.'
            elif 'pattern_match' in str(f.metadata):
                rationale += '. This process matches patterns that may indicate unusual or potentially unauthorized activity, though the risk level is currently assessed as low.'
            
            tags_str = ', '.join(f.tags or [])
            risk_breakdown = f.risk_subscores
            risk_details = ''
            if risk_breakdown:
                risk_details = f"<br><small>Risk factors - Impact: {risk_breakdown.get('impact', 'N/A')}, Exposure: {risk_breakdown.get('exposure', 'N/A')}, Anomaly: {risk_breakdown.get('anomaly', 'N/A')}, Confidence: {risk_breakdown.get('confidence', 'N/A')}</small>"
            
            low_analysis += f"<li><strong>{html.escape(f.id)}</strong><br><em>{html.escape(rationale)}</em>{risk_details}<br><small>Risk Score: {f.risk_total or f.risk_score}, Tags: {tags_str}, Baseline: {f.baseline_status or 'unknown'}</small></li>"
        low_analysis += f"""
        </ul>
        <h3>Recommended Actions</h3>
        <ol>
        <li>Address during routine maintenance or system upgrades</li>
        <li>Document for future reference</li>
        <li>Consider bulk remediation approaches</li>
        <li>Monitor for patterns that might indicate larger issues</li>
        </ol>
        </section>
        """
        risk_analysis_sections.append(low_analysis)
    
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
{''.join(risk_analysis_sections)}
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
