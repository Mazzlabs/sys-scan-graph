from __future__ import annotations
"""Risk scoring utilities with calibratable weights.

Formula:
  risk_total = ((impact * W1) + (exposure * W2) + (anomaly * W3)) * confidence

Weights are loaded in order of precedence:
  1. In-memory overrides passed to compute_risk
  2. JSON file agent_risk_weights.json in CWD (schema: {"impact":5,"exposure":3,"anomaly":2})
  3. Environment variables RISK_W_IMPACT, RISK_W_EXPOSURE, RISK_W_ANOMALY
  4. Defaults (impact=5, exposure=3, anomaly=2)

Scaling: We normalize to 0-100 by dividing by the theoretical maximum given
current observed caps (impact<=10, exposure<=3, anomaly<=2) * weights.
This maintains comparable magnitude even if weights shift.
"""
from dataclasses import dataclass
from pathlib import Path
import json, os
from typing import Dict, Tuple

DEFAULT_WEIGHTS = {"impact":5.0, "exposure":3.0, "anomaly":2.0}
CAPS = {"impact":10.0, "exposure":3.0, "anomaly":2.0}
WEIGHTS_FILE = Path("agent_risk_weights.json")

def load_persistent_weights() -> Dict[str,float]:
    if WEIGHTS_FILE.exists():
        try:
            data = json.loads(WEIGHTS_FILE.read_text())
            return {k: float(data.get(k, DEFAULT_WEIGHTS[k])) for k in DEFAULT_WEIGHTS}
        except Exception:
            return DEFAULT_WEIGHTS.copy()
    # env fallback
    result = DEFAULT_WEIGHTS.copy()
    for k, env_name in [("impact","RISK_W_IMPACT"),("exposure","RISK_W_EXPOSURE"),("anomaly","RISK_W_ANOMALY")]:
        try:
            if env_name in os.environ:
                result[k] = float(os.environ[env_name])
        except ValueError:
            pass
    return result

def save_persistent_weights(weights: Dict[str,float]):
    WEIGHTS_FILE.write_text(json.dumps(weights, indent=2))

def compute_risk(subscores: Dict[str,float], weights: Dict[str,float] | None = None) -> Tuple[int,float]:
    if weights is None:
        weights = load_persistent_weights()
    impact = float(subscores.get("impact",0.0))
    exposure = float(subscores.get("exposure",0.0))
    anomaly = float(subscores.get("anomaly",0.0))
    confidence = float(subscores.get("confidence",1.0))
    raw = impact * weights["impact"] + exposure * weights["exposure"] + anomaly * weights["anomaly"]
    max_raw = CAPS["impact"] * weights["impact"] + CAPS["exposure"] * weights["exposure"] + CAPS["anomaly"] * weights["anomaly"]
    scaled = 0.0 if max_raw <= 0 else (raw / max_raw) * 100.0
    final_score = int(round(min(100, max(0, scaled * confidence))))
    return final_score, raw

def describe(weights: Dict[str,float] | None = None) -> Dict[str,float]:
    if weights is None:
        weights = load_persistent_weights()
    max_raw = CAPS["impact"] * weights["impact"] + CAPS["exposure"] * weights["exposure"] + CAPS["anomaly"] * weights["anomaly"]
    return {**weights, "_max_raw": max_raw}
