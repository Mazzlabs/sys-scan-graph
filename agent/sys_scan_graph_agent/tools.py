from __future__ import annotations
"""LangChain tool definitions for agentic graph behaviors.

Currently provides a baseline query tool that (stub) determines whether a
finding appears to be new or recurring. A future enhancement can integrate
direct BaselineStore lookups using the finding identity hash + scanner.
"""

from typing import Dict, Any
import os, sqlite3, hashlib
from pathlib import Path
try:
    from .baseline import hashlib_sha  # reuse composite hash helper
except Exception:  # pragma: no cover
    def hashlib_sha(scanner: str, h: str) -> str:
        dig = hashlib.sha256(); dig.update(scanner.encode()); dig.update(b":"); dig.update(h.encode()); return dig.hexdigest()

try:  # Optional dependency: only decorate if langchain_core present
    from langchain_core.tools import tool  # type: ignore
except Exception:  # pragma: no cover
    def tool(fn):  # type: ignore
        return fn


@tool
def query_baseline(finding_id: str, title: str = "", severity: str = "", scanner: str = "mixed", host_id: str | None = None) -> Dict[str, Any]:
    """Query baseline DB for existence of a finding (no mutation).

    Args:
        finding_id: ID field from finding.
        title: Title of finding (for identity hash stability).
        severity: Severity string.
        scanner: Scanner name (used in composite hash) default 'mixed'.
        host_id: Host identifier; defaults to AGENT_GRAPH_HOST_ID or 'graph_host'.
    Returns dict with status=new|existing|error and metadata.
    """
    db_path = os.environ.get('AGENT_BASELINE_DB','agent_baseline.db')
    host = host_id or os.environ.get('AGENT_GRAPH_HOST_ID','graph_host')
    identity_core = f"{finding_id}\n{title}\n{severity}\n".encode()
    h = hashlib.sha256(identity_core).hexdigest()
    composite = hashlib_sha(scanner, h)
    out: Dict[str, Any] = {
        'finding_id': finding_id,
        'host_id': host,
        'scanner': scanner,
        'composite_hash': composite,
        'db_path': db_path
    }
    try:
        db_exists = Path(db_path).exists()
        if not db_exists:
            out['status'] = 'new'
            out['note'] = 'baseline db missing'
            out['baseline_db_missing'] = True
            return out
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute("SELECT first_seen_ts, seen_count FROM baseline_finding WHERE host_id=? AND finding_hash=?", (host, composite)).fetchone()
            if row:
                first_seen, count = row
                out['status'] = 'existing'
                out['first_seen_ts'] = first_seen
                out['prev_seen_count'] = count
                out['baseline_db_missing'] = False
            else:
                out['status'] = 'new'
                out['baseline_db_missing'] = False
        finally:
            conn.close()
    except Exception as e:  # pragma: no cover
        out['status'] = 'error'
        out['error'] = str(e)
        # If error occurs after existence check, we can still state whether DB existed
        out['baseline_db_missing'] = out.get('baseline_db_missing', not Path(db_path).exists())
    return out

__all__ = ["query_baseline"]
