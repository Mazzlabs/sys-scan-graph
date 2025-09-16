from __future__ import annotations
import shlex
from pathlib import Path
import sys_scan_graph_agent.sandbox as sandbox

run_command = sandbox.run_command

def query_package_manager(path: str | Path) -> dict:
    """Attempt to attribute a binary to a package using dpkg -S (Debian-based) as a best-effort.
    Returns {package, raw} if found else {}.
    Safe bounded: runs dpkg -S with a timeout and sanitized path.
    """
    p = Path(path)
    if not p.exists():
        return {"error": "missing"}
    cmd = ["bash","-lc", f"dpkg -S {shlex.quote(str(p))} 2>/dev/null | head -n1"]
    res = run_command(cmd)
    out = res.get('output') if 'output' in res else ''
    if not out:
        return res if 'error' in res or 'dry_run' in res else {}
    if ':' in out:
        pkg = out.split(':',1)[0]
    else:
        pkg = out
    res.update({"package": pkg})
    return res
