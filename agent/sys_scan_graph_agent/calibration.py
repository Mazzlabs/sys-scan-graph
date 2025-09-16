from __future__ import annotations
"""Calibration model loader & application.

Supports logistic curve mapping raw weighted sum -> probability_actionable.
Calibration file schema (agent_risk_calibration.json):
{
  "version": "2025-08-26_initial",
  "type": "logistic",
  "params": {"a": -3.0, "b": 0.15}
}
"""
from pathlib import Path
import json, math
from typing import Dict

CALIBRATION_FILE = Path("agent_risk_calibration.json")
DEFAULT_CALIBRATION = {"version": "default_untrained", "type": "logistic", "params": {"a": -3.0, "b": 0.15}}

def load_calibration() -> Dict:
    if CALIBRATION_FILE.exists():
        try:
            data = json.loads(CALIBRATION_FILE.read_text())
            if data.get("type") == "logistic" and "params" in data:
                return data
        except Exception:
            pass
    return DEFAULT_CALIBRATION

def save_calibration(cal: Dict):
    CALIBRATION_FILE.write_text(json.dumps(cal, indent=2))

def logistic(a: float, b: float, x: float) -> float:
    try:
        return 1.0 / (1.0 + math.exp(-(a + b * x)))
    except OverflowError:
        return 0.0 if (a + b * x) < 0 else 1.0

def apply_probability(raw_weighted_sum: float) -> float:
    cal = load_calibration()
    if cal["type"] == "logistic":
        a = float(cal["params"].get("a", -3.0))
        b = float(cal["params"].get("b", 0.15))
        return round(logistic(a,b,raw_weighted_sum),4)
    return 0.0