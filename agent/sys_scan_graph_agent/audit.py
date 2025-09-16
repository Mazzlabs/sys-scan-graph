from __future__ import annotations
import json, os, time, hashlib
from pathlib import Path
from typing import Iterable, List, Dict, Any

DEFAULT_LOG = Path("agent_audit.log")

def _log_path() -> Path:
    p = os.environ.get('AGENT_AUDIT_LOG')
    return Path(p) if p else DEFAULT_LOG

def append(record: Dict[str, Any]):
    rec = record.copy()
    rec.setdefault('ts', time.time())
    rec.setdefault('version', 1)
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as f:
        f.write(json.dumps(rec, separators=(',',':')) + '\n')

def log_stage(stage: str, **fields):
    append({'stage': stage, **fields})

def parse_duration(spec: str) -> float:
    spec = spec.strip().lower()
    if spec.endswith('ms'): return max(0, float(spec[:-2]) / 1000.0)
    mult = 1.0
    if spec.endswith('s'):
        mult = 1.0; spec = spec[:-1]
    elif spec.endswith('m'):
        mult = 60.0; spec = spec[:-1]
    elif spec.endswith('h'):
        mult = 3600.0; spec = spec[:-1]
    elif spec.endswith('d'):
        mult = 86400.0; spec = spec[:-1]
    try:
        return float(spec) * mult
    except ValueError:
        return 0.0

def tail_since(duration_spec: str, limit: int = 200) -> List[Dict[str,Any]]:
    path = _log_path()
    if not path.exists():
        return []
    horizon = time.time() - parse_duration(duration_spec)
    out: List[Dict[str,Any]] = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = obj.get('ts') or 0
            if ts >= horizon:
                out.append(obj)
    # Return last N chronologically (file already chronological append-only)
    if len(out) > limit:
        out = out[-limit:]
    return out

def hash_text(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()
