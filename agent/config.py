from __future__ import annotations
from pydantic import BaseModel, Field, ValidationError
from pathlib import Path
import yaml, os, json, hashlib, inspect
from typing import List, Dict, Any, Optional

DEFAULT_CONFIG_PATH = Path('config.yaml')

class Weights(BaseModel):
    impact: float = 1.0
    exposure: float = 1.0
    anomaly: float = 1.0

class Notifications(BaseModel):
    slack_webhook: Optional[str] = None
    webhook: Optional[str] = None  # generic HTTP POST endpoint
    actionable_delta_threshold: float = 0.15  # probability_actionable delta trigger

class Reports(BaseModel):
    html_enabled: bool = True
    html_path: str = 'enriched_report.html'
    diff_markdown_path: str = 'enriched_diff.md'

class Performance(BaseModel):
    parallel_baseline: bool = False
    workers: int = 4

class Thresholds(BaseModel):
    summarization_risk_sum: int = 150
    process_novelty_distance: float = 0.35
    metric_drift_z: float = 2.5

class Paths(BaseModel):
    rule_dirs: List[str] = Field(default_factory=list)
    policy_allowlist: List[str] = Field(default_factory=list)

class Bundle(BaseModel):
    manifest_path: str = 'manifest.json'

class Config(BaseModel):
    weights: Weights = Weights()
    notifications: Notifications = Notifications()
    reports: Reports = Reports()
    performance: Performance = Performance()
    thresholds: Thresholds = Thresholds()
    paths: Paths = Paths()
    bundle: Bundle = Bundle()

_cached_config: Optional[Config] = None


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> Config:
    global _cached_config
    if _cached_config is not None:
        return _cached_config
    data: Dict[str, Any] = {}
    if path.exists():
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except Exception:
            data = {}
    # Env overrides (simple flat mapping e.g. AGENT_WEIGHT_IMPACT=1.2)
    try:
        w_imp = os.environ.get('AGENT_WEIGHT_IMPACT'); w_exp = os.environ.get('AGENT_WEIGHT_EXPOSURE'); w_anom = os.environ.get('AGENT_WEIGHT_ANOMALY')
        if w_imp: data.setdefault('weights', {})['impact'] = float(w_imp)
        if w_exp: data.setdefault('weights', {})['exposure'] = float(w_exp)
        if w_anom: data.setdefault('weights', {})['anomaly'] = float(w_anom)
    except ValueError:
        pass
    try:
        _cached_config = Config.model_validate(data)
    except ValidationError as e:
        raise SystemExit(f'Invalid config.yaml: {e}')
    return _cached_config

# -------- Manifest Helpers ---------

def compute_rule_pack_sha(rule_dirs: List[str]) -> str:
    import rules
    all_rules = []
    for rd in rule_dirs:
        all_rules.extend(rules.load_rules_dir(rd))
    # stable sorted JSON
    payload = json.dumps(sorted(all_rules, key=lambda r: r.get('id','')), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()

def embedding_model_hash() -> str:
    try:
        import baseline
        src = inspect.getsource(baseline.process_feature_vector)
    except Exception:
        src = 'baseline:process_feature_vector'
    return hashlib.sha256(src.encode()).hexdigest()

def agent_version() -> str:
    # Parse first semantic version from CHANGELOG.md
    ch = Path('CHANGELOG.md')
    if ch.exists():
        for line in ch.read_text().splitlines():
            line = line.strip()
            if line.startswith('##') and any(c.isdigit() for c in line):
                # crude extraction
                toks = line.replace('#','').strip().split()
                for t in toks:
                    if t[0].isdigit():
                        return t
    return '0.0.0'

def build_manifest(cfg: Config) -> Dict[str, Any]:
    manifest = {
        'version': agent_version(),
        'rule_pack_sha': compute_rule_pack_sha(cfg.paths.rule_dirs) if cfg.paths.rule_dirs else None,
        'weights': cfg.weights.model_dump(),
        'embedding_model_hash': embedding_model_hash(),
    }
    return manifest

def write_manifest(cfg: Config):
    man = build_manifest(cfg)
    try:
        Path(cfg.bundle.manifest_path).write_text(json.dumps(man, indent=2))
    except Exception:
        pass
    return man
