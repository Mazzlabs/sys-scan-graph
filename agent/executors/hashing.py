from __future__ import annotations
from pathlib import Path
import hashlib
import sys_scan_graph_agent.sandbox as sandbox

SANDBOX = sandbox.SANDBOX

def hash_binary(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return {"error": "missing"}
    if SANDBOX.dry_run:
        return {"dry_run": True, "cmd": ["hash_binary", str(p)]}
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return {"sha256": h.hexdigest(), "size": p.stat().st_size}
