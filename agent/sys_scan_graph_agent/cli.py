from __future__ import annotations
import json
from pathlib import Path
import typer
from rich import print
import rules
import baseline
import integrity
import audit
import rule_gap_miner
import rarity_generate
import sandbox
import risk
import calibration
import config
import report_html
import report_diff
import graph_nodes_scaffold
import graph_state
import time
from jsonschema import validate as js_validate, ValidationError
# Phase 10 imports
import os
import urllib.request

def run_scaffold_workflow(report_path: Path) -> tuple:
    """Run the scaffold workflow and return enriched output and final state with metrics."""
    # Load the report data
    import json
    raw_data = json.loads(report_path.read_text())
    
    # Initialize state
    initial_state = {
        'raw_findings': raw_data.get('results', [{}])[0].get('findings', []) if raw_data.get('results') else [],
        'enriched_findings': [],
        'correlated_findings': [],
        'suggested_rules': [],
        'summary': {},
        'warnings': [],
        'correlations': [],
        'messages': [],
        'baseline_results': {},
        'baseline_cycle_done': False,
        'iteration_count': 0,
        'metrics': {},
        'cache_keys': [],
        'enrich_cache': {},
        'streaming_enabled': False,
        'human_feedback_pending': False,
        'pending_tool_calls': [],
        'risk_assessment': {},
        'compliance_check': {},
        'errors': [],
        'degraded_mode': False,
        'human_feedback_processed': False,
        'final_metrics': {},
        'cache': {},
        'llm_provider_mode': 'normal'
    }
    
    # Normalize initial state
    state = normalize_graph_state(initial_state)
    
    # Run scaffold workflow
    try:
        state = enrich_findings(state)
        state = correlate_findings(state)
        state = scaffold_summarize(state)
        state = scaffold_suggest_rules(state)
        # Run async nodes
        import asyncio
        async def run_async_nodes():
            s = await risk_analyzer(state)
            s = await compliance_checker(s)
            s = await metrics_collector(s)
            return s
        
        # Run async workflow
        final_state = asyncio.run(run_async_nodes())
        
        # Create enriched output (simplified version)
        from models import EnrichedOutput, Reductions, Summaries
        enriched = EnrichedOutput(
            correlations=final_state.get('correlations', []),
            reductions=Reductions(),
            summaries=Summaries(),
            actions=[],
            enriched_findings=final_state.get('enriched_findings', [])
        )
        
        return enriched, final_state
        
    except Exception as e:
        print(f"[red]Scaffold workflow failed: {e}[/red]")
        raise

app = typer.Typer(help="sys-scan intelligence layer (agent MVP)")

@app.command()
def analyze(report: Path = typer.Option(..., exists=True, readable=True, help="Path to sys-scan JSON report"),
            out: Path = typer.Option("enriched_report.json", help="Output enriched JSON path"),
            checkpoint_dir: Path = typer.Option(None, help="Directory to write per-node state checkpoints"),
            schema: Path = typer.Option(None, help="Path to JSON schema for validation"),
            index_dir: Path = typer.Option(None, help="Directory to append time-series index entries"),
            dry_run: bool = typer.Option(False, help="Sandbox dry-run (no external commands executed)"),
            prev: Path = typer.Option(None, help="Previous enriched report for diff"),
            metrics_out: Path = typer.Option(None, help="Export node telemetry metrics to file (supports .json, .csv, .prom extensions)")):
    cfg = load_config()
    if dry_run:
        sandbox_config(dry_run=True)
    enriched, final_state = run_scaffold_workflow(report)
    out.write_text(enriched.model_dump_json(indent=2))
    print(f"[green]Wrote enriched output -> {out} (Scaffold mode)")

    # Export metrics if requested
    if metrics_out:
        try:
            from metrics_exporter import export_all_formats, print_metrics_summary

            # Determine export format from file extension
            if str(metrics_out).endswith('.json'):
                from metrics_exporter import write_metrics_json
                write_metrics_json(metrics_state, str(metrics_out))
                print(f"[cyan]Metrics exported to JSON -> {metrics_out}")
            elif str(metrics_out).endswith('.csv'):
                from metrics_exporter import export_metrics_csv
                export_metrics_csv(metrics_state, str(metrics_out))
                print(f"[cyan]Metrics exported to CSV -> {metrics_out}")
            elif str(metrics_out).endswith('.prom'):
                from metrics_exporter import export_prometheus
                export_prometheus(metrics_state, str(metrics_out))
                print(f"[cyan]Metrics exported to Prometheus -> {metrics_out}")
            else:
                # Default to JSON if no extension or unknown
                from metrics_exporter import write_metrics_json
                write_metrics_json(metrics_state, str(metrics_out))
                print(f"[cyan]Metrics exported to JSON -> {metrics_out}")

            # Always print summary to console
            print_metrics_summary(metrics_state)

        except Exception as e:
            print(f"[red]Metrics export failed: {e}")
    # HTML artifact
    if cfg.reports.html_enabled:
        report_html.write_html(enriched, Path(cfg.reports.html_path))
        print(f"[cyan]HTML report -> {cfg.reports.html_path}")
    # Diff markdown
    if prev and prev.exists():
        try:
            from models import EnrichedOutput
            prev_obj = EnrichedOutput.model_validate(json.loads(prev.read_text()))
            report_diff.write_diff(prev_obj, enriched, Path(cfg.reports.diff_markdown_path))
            print(f"[cyan]Diff markdown -> {cfg.reports.diff_markdown_path}")
            # Notification trigger
            prob_prev = [f.probability_actionable or 0 for f in prev_obj.enriched_findings or []]
            prob_curr = [f.probability_actionable or 0 for f in enriched.enriched_findings or []]
            avg_prev = sum(prob_prev)/len(prob_prev) if prob_prev else 0
            avg_curr = sum(prob_curr)/len(prob_curr) if prob_curr else 0
            delta = avg_curr - avg_prev
            high_new = any((f.severity or '').lower() == 'high' and any(t == 'baseline:new' for t in (f.tags or [])) for f in enriched.enriched_findings or [])
            if (high_new or delta >= cfg.notifications.actionable_delta_threshold):
                _notify(cfg, message=f"sys-scan: delta_prob={delta:+.2f} high_new={high_new} report={out}")
        except Exception as e:
            print(f"[red]Diff/notify error: {e}")
    # Manifest
    config.write_manifest(cfg)
    if checkpoint_dir:
        print(f"[cyan]Checkpoints in {checkpoint_dir}")
    if index_dir:
        print(f"[cyan]Index updated at {index_dir}/index.json")

@app.command()
def validate_report(report: Path = typer.Option(..., exists=True, help="Path to raw v2 report"),
                    schema: Path = typer.Option(Path("schema/v2.json"), help="Schema path"),
                    max_ms: int = typer.Option(500, help="Wall time budget (ms)")):
    start = time.time()
    data = json.loads(report.read_text())
    try:
        sch = json.loads(schema.read_text())
        js_validate(instance=data, schema=sch)
    except FileNotFoundError:
        print(f"[red]Schema file not found: {schema}")
        raise typer.Exit(code=2)
    except ValidationError as e:
        print(f"[red]Schema validation error: {e.message}[/red]")
        raise typer.Exit(code=3)
    enriched, _ = run_scaffold_workflow(report)
    elapsed_ms = int((time.time() - start)*1000)
    print(f"[green]Validation OK[/green] elapsed_ms={elapsed_ms} findings={data.get('summary',{}).get('finding_count_total')} correlations={len(enriched.correlations)}")
    if elapsed_ms > max_ms:
        print(f"[red]Exceeded time budget {elapsed_ms}ms > {max_ms}ms[/red]")
        raise typer.Exit(code=4)

@app.command()
def validate_batch(dir: Path = typer.Option(..., exists=True, help="Directory containing report JSON fixtures"),
                   schema: Path = typer.Option(Path("schema/v2.json"), help="Schema path"),
                   max_ms: int = typer.Option(500, help="Per-report time budget ms"),
                   require: int = typer.Option(6, help="Minimum number of reports to validate")):
    files = [p for p in dir.glob('*.json')]
    if len(files) < require:
        print(f"[red]Not enough fixtures: found {len(files)} need {require}")
        raise typer.Exit(code=5)
    try:
        sch = json.loads(schema.read_text())
    except FileNotFoundError:
        print(f"[red]Schema file not found: {schema}")
        raise typer.Exit(code=6)
    worst = 0
    for p in files:
        start = time.time()
        data = json.loads(p.read_text())
        try:
            js_validate(instance=data, schema=sch)
        except ValidationError as e:
            print(f"[red]{p.name}: schema_error {e.message}")
            raise typer.Exit(code=7)
        run_scaffold_workflow(p)
        ms = int((time.time()-start)*1000)
        worst = max(worst, ms)
        print(f"[green]{p.name} OK[/green] {ms}ms")
    print(f"[cyan]Batch complete worst_case_ms={worst} (budget {max_ms}ms)")
    if worst > max_ms:
        print(f"[red]Time budget exceeded: {worst}>{max_ms}")
        raise typer.Exit(code=8)

@app.command()
def risk_weights(show: bool = typer.Option(False, help="Show current weights"),
                 impact: float = typer.Option(None, help="Set impact weight"),
                 exposure: float = typer.Option(None, help="Set exposure weight"),
                 anomaly: float = typer.Option(None, help="Set anomaly weight")):
    w = risk.load_persistent_weights()
    changed = False
    if impact is not None:
        w["impact"] = impact; changed = True
    if exposure is not None:
        w["exposure"] = exposure; changed = True
    if anomaly is not None:
        w["anomaly"] = anomaly; changed = True
    if changed:
        risk.save_persistent_weights(w)
        print(f"[green]Weights updated -> {w}")
    if show or not changed:
        print(risk.describe(w))

@app.command()
def risk_calibration(show: bool = typer.Option(False, help="Show current calibration"),
                     version: str = typer.Option(None, help="Set calibration version label"),
                     a: float = typer.Option(None, help="Logistic 'a' intercept"),
                     b: float = typer.Option(None, help="Logistic 'b' slope")):
    cal = calibration.load_calibration()
    changed = False
    if a is not None or b is not None:
        cal['params']['a'] = a if a is not None else cal['params']['a']
        cal['params']['b'] = b if b is not None else cal['params']['b']
        changed = True
    if version is not None:
        cal['version'] = version; changed = True
    if changed:
        calibration.save_calibration(cal)
        print(f"[green]Calibration updated -> {cal}")
    if show or not changed:
        print(cal)

@app.command()
def risk_decision(report: Path = typer.Option(..., exists=True, help="Raw v2 report JSON"),
                  finding_id: str = typer.Option(...),
                  decision: str = typer.Option(..., help="tp|fp|ignore"),
                  db: Path = typer.Option(Path("agent_baseline.db"))):
    # Re-run pipeline to ensure we have composite hash mapping
    enriched, _ = run_scaffold_workflow(report)
    # Need to reconstruct finding composite hash using scanner
    raw = json.loads(report.read_text())
    host_id = raw.get('meta',{}).get('host_id') or enriched.enriched_findings[0].metadata.get('host_id','unknown_host') if enriched.enriched_findings else 'unknown_host'
    # Build map from id to composite hash
    from baseline import hashlib_sha
    composite_map = {}
    for sr in raw.get('results', []):
        scanner = sr.get('scanner')
        for f in sr.get('findings', []):
            if f.get('id') == finding_id:
                # Need identity hash as in baseline store
                h = hashlib_sha(scanner, hashlib_sha(scanner, f.get('id')))
    # Simpler: just iterate baseline DB observations not ideal; fallback: use id alone
    store = baseline.BaselineStore(db)
    try:
        store.update_calibration_decision(host_id, finding_id, decision)
        print(f"[green]Decision recorded for {finding_id}: {decision}")
    except Exception as e:
        print(f"[red]Failed to record decision: {e}")

    @app.command()
    def rule_lint(rules_dir: Path = typer.Option(..., exists=True, help="Directory with rule files (.json/.yml/.yaml)")):
        rules_data = rules.load_rules_dir(str(rules_dir))
        issues = rules.lint_rules(rules_data)
        if not issues:
            print("[green]No lint issues detected")
            raise typer.Exit(code=0)
        for i in issues:
            print(f"[yellow]{i['rule_id']}[/yellow] {i['code']} {i['detail']}")
        raise typer.Exit(code=1)

    @app.command()
    def rule_dry_run(rules_dir: Path = typer.Option(..., exists=True),
                     findings_json: Path = typer.Option(..., exists=True, help="JSON array of findings to test")):
        from models import Finding
        data = json.loads(findings_json.read_text())
        rules = load_rules_dir(str(rules_dir))
        findings = []
        for obj in data:
            findings.append(Finding(
                id=obj.get('id'),
                title=obj.get('title','(no title)'),
                severity=obj.get('severity','info'),
                risk_score=obj.get('risk_score',0),
                metadata=obj.get('metadata',{})
            ))
        matches = dry_run_apply(rules, findings)
        for rid, m in matches.items():
            if m:
                print(f"[cyan]{rid}[/cyan]: {', '.join(m)}")
            else:
                print(f"[dim]{rid}[/dim]: (no matches)")

    @app.command()
    def baseline_integrity(db: Path = typer.Option(Path("agent_baseline.db")),
                           host: str = typer.Option(..., help="Host ID"),
                           days: int = typer.Option(7, help="Look back days for continuity")):
        store = baseline.BaselineStore(db)
        days_map = store.scan_days_present(host, days)
        missing = [d for d, present in days_map.items() if not present]
        for d, present in sorted(days_map.items()):
            mark = "OK" if present else "MISSING"
            color = "green" if present else "red"
            print(f"[{color}]{d}[/] {mark}")
        if missing:
            print(f"[red]Missing {len(missing)} day(s) in last {days}d window[/red]")

@app.command()
def rarity_generate_cmd(db: Path = typer.Option(Path("agent_baseline.db"), help="Baseline DB path"),
                        out: Path = typer.Option(Path("rarity.yaml"), help="Output rarity YAML")):
    path = rarity_generate(db, out)
    print(f"[green]Generated rarity file {path}")

@app.command()
def sandbox(dry_run: bool = typer.Option(None), timeout: float = typer.Option(None), max_output: int = typer.Option(None)):
    cfg = sandbox.configure(dry_run=dry_run, timeout_sec=timeout, max_output_bytes=max_output)
    print(f"[green]Sandbox updated[/green] {cfg.model_dump()}")

    @app.command()
    def baseline_diff(db: Path = typer.Option(Path("agent_baseline.db")),
                      host: str = typer.Option(..., help="Host ID"),
                      since: str = typer.Option("7d", help="Duration spec (e.g. 7d, 24h)")):
        # Parse simple duration
        mult = 1
        val = since
        if since.endswith('d'):
            mult = 86400
            val = since[:-1]
        elif since.endswith('h'):
            mult = 3600
            val = since[:-1]
        try:
            qty = int(val)
        except ValueError:
            print("[red]Invalid duration format[/red]")
            raise typer.Exit(code=2)
        seconds = qty * mult
        days = max(1, seconds // 86400)
        store = baseline.BaselineStore(db)
        recent = store.diff_since_days(host, days)
        print(json.dumps(recent, indent=2))

def build_fleet_report(db: Path, top_n: int = 5, recent_seconds: int = 86400, module_min_hosts: int = 3) -> dict:
    """Return fleet report object (not written to disk)."""
    store = baseline.BaselineStore(db)
    # 1. Collect latest finding.count.total per host
    latest = store.latest_metric_values('finding.count.total')
    host_values = [v for (_,v,_) in latest]
    import math
    mean = sum(host_values)/len(host_values) if host_values else 0.0
    var = sum((v-mean)**2 for v in host_values)/(len(host_values)-1) if len(host_values) > 1 else 0.0
    std = math.sqrt(var)
    hosts_stats = []
    for host_id, value, ts in latest:
        z = (value-mean)/std if std else 0.0
        hosts_stats.append({"host_id": host_id, "value": value, "z": z, "ts": ts})
    top_outlier_hosts = sorted(hosts_stats, key=lambda x: abs(x['z']), reverse=True)[:top_n]
    # 2. Newly common modules: modules whose first_seen across >= module_min_hosts hosts within recent_seconds
    recent_map = store.recent_module_first_seen(within_seconds=recent_seconds)
    newly_common_modules = [
        {"module": m, "host_count": len(hs), "hosts": hs}
        for m, hs in recent_map.items() if len(hs) >= module_min_hosts
    ]
    # 3. Risk distribution histogram: we approximate using latest risk.sum.medium_high metric per host (if present)
    risk_latest = store.latest_metric_values('risk.sum.medium_high')
    risk_values = [v for (_,v,_) in risk_latest]
    # Bucket edges (log-ish or simple linear). We'll use simple linear 0-50,50-100,... up to 500
    buckets = list(range(0, 501, 50))
    histogram = []
    for i in range(len(buckets)-1):
        lo, hi = buckets[i], buckets[i+1]
        cnt = sum(1 for v in risk_values if lo <= v < hi)
        histogram.append({"range": f"{lo}-{hi-1}", "count": cnt})
    if risk_values:
        cnt = sum(1 for v in risk_values if v >= buckets[-1])
        histogram.append({"range": f">={buckets[-1]}", "count": cnt})
    return {
        "generated_ts": int(__import__('time').time()),
        "host_count": len(host_values),
        "metric_mean": mean,
        "metric_std": std,
        "top_outlier_hosts": top_outlier_hosts,
        "newly_common_modules": newly_common_modules,
        "risk_distribution": histogram
    }
@app.command("fleet-report")
def fleet_report_cmd(db: Path = typer.Option(Path("agent_baseline.db"), help="Baseline DB path"),
                     out: Path = typer.Option(Path("fleet_report.json"), help="Output JSON path"),
                     top_n: int = typer.Option(5, help="Top outlier hosts count"),
                     recent_seconds: int = typer.Option(86400, help="Window for newly common modules (seconds)"),
                     module_min_hosts: int = typer.Option(3, help="Threshold hosts for 'newly common' modules")):
    obj = build_fleet_report(db, top_n=top_n, recent_seconds=recent_seconds, module_min_hosts=module_min_hosts)
    out.write_text(json.dumps(obj, indent=2))
    print(f"[green]Wrote fleet report -> {out}")

@app.command("audit-tail")
def audit_tail(since: str = typer.Option("1h", help="Duration spec e.g. 30m, 2h, 1d"), limit: int = typer.Option(200, help="Max records")):
    recs = tail_since(since, limit=limit)
    for r in recs:
        print(json.dumps(r))
    print(f"[cyan]{len(recs)} record(s)")

@app.command("rule-gap-mine")
def rule_gap_mine(dir: Path = typer.Option(..., exists=True, file_okay=False, help="Directory of enriched report JSON files"),
                  risk_threshold: int = typer.Option(60, help="Minimum risk_total (unless severity high/critical)"),
                  min_support: int = typer.Option(3, help="Minimum recurrence to suggest"),
                  refine: bool = typer.Option(False, help="Apply LLM heuristic refinement to suggestions"),
                  out: Path = typer.Option(Path('rule_gap_suggestions.json'), help="Output suggestions JSON")):
    files = [p for p in dir.glob('*.json')]
    result = mine_gap_candidates(files, risk_threshold=risk_threshold, min_support=min_support)
    if refine and result.get('suggestions'):
        # Build map id -> example titles (from candidates info)
        ex_map = {}
        for c in result.get('candidates', []):
            rid_guess = f"gap_{c['key'][:40]}"
            ex_map[rid_guess] = c.get('example_titles', [])
        refined = refine_with_llm(result['suggestions'], examples=ex_map)
        result['suggestions'] = refined
        result['refined'] = True
    out.write_text(json.dumps(result, indent=2))
    print(f"[green]Wrote suggestions -> {out} selected={result['selected']} total_candidates={result['total_candidates']} refined={result.get('refined', False)}")

@app.command()
def keygen(out_dir: Path = typer.Option(Path('.'), help='Directory to write keypair'), prefix: str = typer.Option('agent', help='Filename prefix')):
    sk_b64, vk_b64 = generate_keypair()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f'{prefix}.sk').write_text(sk_b64 + '\n')
    (out_dir / f'{prefix}.vk').write_text(vk_b64 + '\n')
    print(f"[green]Generated keypair[/green] sk={out_dir / (prefix + '.sk')} vk={out_dir / (prefix + '.vk')}")

@app.command()
def sign(report: Path = typer.Option(..., exists=True, help='Raw report path'),
         signing_key: Path = typer.Option(..., exists=True, help='Base64 signing key file')):
    sk_b64 = signing_key.read_text().strip()
    digest, sig_b64 = sign_file(report, sk_b64)
    print(f"[green]Signed[/green] sha256={digest} sig_len={len(sig_b64)}")

@app.command()
def verify(report: Path = typer.Option(..., exists=True, help='Raw report path'),
           verify_key: Path = typer.Option(..., exists=True, help='Base64 verify key file')):
    vk_b64 = verify_key.read_text().strip()
    status = verify_file(report, vk_b64)
    ok = status.get('digest_match') and status.get('signature_valid')
    color = 'green' if ok else 'red'
    print(f"[{color}]Verification status[/] {json.dumps(status)}")
    if not ok:
        raise typer.Exit(code=10)

@app.command("verify-signature")
def verify_signature(report: Path = typer.Option(..., exists=True, help='Raw report path'),
                     verify_key: Path = typer.Option(..., exists=True, help='Base64 verify key file')):
    return verify(report=report, verify_key=verify_key)

# Notification helper

def _notify(cfg, message: str):
    payload = json.dumps({'text': message}).encode()
    url = cfg.notifications.slack_webhook or cfg.notifications.webhook
    if not url:
        return
    try:
        req = urllib.request.Request(url, data=payload, headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=2) as resp:
            resp.read()
    except Exception as e:
        print(f"[red]Notification failed: {e}")

if __name__ == "__main__":
    app()
