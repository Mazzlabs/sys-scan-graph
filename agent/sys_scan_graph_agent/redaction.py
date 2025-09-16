from __future__ import annotations
import re, json
from copy import deepcopy
from pathlib import Path
from typing import List, Pattern, Dict, Any
from . import models

DEFAULT_RULES = [
    {"pattern": r"/home/([A-Za-z0-9_.-]+)", "replacement": "/home/<user>"},
    {"pattern": r"/Users/([A-Za-z0-9_.-]+)", "replacement": "/Users/<user>"},
]

CONFIG_FILES = [
    Path("agent_redaction.yaml"),
    Path(__file__).parent / "redaction_config.yaml",
]

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

class RedactionRule:
    def __init__(self, pattern: str, replacement: str):
        self.pattern = pattern
        self.replacement = replacement
        self._compiled: Pattern[str] = re.compile(pattern)

    def apply(self, text: str) -> str:
        return self._compiled.sub(self.replacement, text)


def load_rules() -> List[RedactionRule]:
    rules_def = []
    # load from first existing config file
    for p in CONFIG_FILES:
        if p.exists() and yaml:
            try:
                data = yaml.safe_load(p.read_text()) or {}
                rules_def.extend(data.get("redactions", []))
                break
            except Exception:
                pass
    if not rules_def:
        rules_def = DEFAULT_RULES
    extra_env = Path("AGENT_REDACTION_EXTRA").read_text() if Path("AGENT_REDACTION_EXTRA").exists() else None
    if extra_env:
        try:
            rules_def.extend(json.loads(extra_env))
        except Exception:
            pass
    rules: List[RedactionRule] = []
    seen = set()
    for r in rules_def:
        pat = r.get("pattern") if isinstance(r, dict) else None
        rep = r.get("replacement") if isinstance(r, dict) else None
        if isinstance(pat, str) and isinstance(rep, str) and pat not in seen:
            seen.add(pat)
            try:
                rules.append(RedactionRule(pat, rep))
            except re.error:
                continue
    if not rules:
        # Fallback to defaults if all invalid
        rules = [RedactionRule(d["pattern"], d["replacement"]) for d in DEFAULT_RULES]
    return rules

_RULE_CACHE: List[RedactionRule] | None = None


def get_rules() -> List[RedactionRule]:
    global _RULE_CACHE
    if _RULE_CACHE is None:
        _RULE_CACHE = load_rules()
    return _RULE_CACHE


def redact_text(text: str) -> str:
    if not text:
        return text
    for r in get_rules():
        text = r.apply(text)
    return text


def redact_obj(obj: Any):  # pragma: no cover small helper
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj


def redact_reductions(reductions: dict) -> dict:
    red = deepcopy(reductions)
    # top_findings / top_risks titles and maybe tags
    new_tf = []
    for f in red.get('top_findings', []):
        f2 = {k: (redact_text(v) if isinstance(v, str) else v) for k, v in f.items()}
        new_tf.append(f2)
    red['top_findings'] = new_tf
    if 'top_risks' in red and red['top_risks'] is not None:
        red['top_risks'] = new_tf
    # Module summary and others: just sanitize string values recursively
    if isinstance(red.get('module_summary'), dict):
        red['module_summary'] = redact_obj(red['module_summary'])
    if isinstance(red.get('suid_summary'), dict):
        red['suid_summary'] = redact_obj(red['suid_summary'])
    if isinstance(red.get('network_summary'), dict):
        red['network_summary'] = redact_obj(red['network_summary'])
    return red
