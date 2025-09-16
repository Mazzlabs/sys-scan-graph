from __future__ import annotations
import json
from pathlib import Path
from typing import List, Dict
from . import pipeline
from . import models
run_pipeline = pipeline.run_pipeline
EnrichedOutput = models.EnrichedOutput

INJECTED_INDICATORS = {
    "compromised_dev_host": [
        # identifiers or titles expected to be elevated
        "Suspicious LD_PRELOAD",
        "TCP 5555 listening",
        "Unexpected SUID bash copy",
    ]
}


def load_fixture(name: str) -> Path:
    base = Path(__file__).parent / 'fixtures' / 'malicious'
    path = base / f'{name}.json'
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def evaluate_fixture(name: str) -> Dict:
    report_path = load_fixture(name)
    enriched: EnrichedOutput = run_pipeline(report_path)
    top = enriched.reductions.top_risks or []
    top_titles = {t['title'] for t in top}
    indicators = INJECTED_INDICATORS.get(name, [])
    hits = [i for i in indicators if any(i in tt for tt in top_titles)]
    detection_rate = 0.0 if not indicators else len(hits) / len(indicators)
    return {
        'fixture': name,
        'indicators_total': len(indicators),
        'indicators_hits': len(hits),
        'detection_rate': detection_rate,
        'hit_indicators': hits,
        'top_risks': top,
    }


def run_evaluation(fixtures: List[str]) -> Dict:
    results = [evaluate_fixture(f) for f in fixtures]
    # overall stats
    total_ind = sum(r['indicators_total'] for r in results)
    total_hits = sum(r['indicators_hits'] for r in results)
    overall_rate = 0.0 if total_ind == 0 else total_hits / total_ind
    return {
        'fixtures': results,
        'overall': {
            'total_indicators': total_ind,
            'total_hits': total_hits,
            'overall_detection_rate': overall_rate,
        }
    }


def write_report(fixtures: List[str], out_path: Path):
    data = run_evaluation(fixtures)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, sort_keys=True))
    return data

if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='Evaluate synthetic attack detection rate.')
    ap.add_argument('--fixtures', nargs='+', default=['compromised_dev_host'])
    ap.add_argument('--out', default='evaluation/report.json')
    args = ap.parse_args()
    data = write_report(args.fixtures, Path(args.out))
    print(json.dumps(data['overall'], indent=2))
