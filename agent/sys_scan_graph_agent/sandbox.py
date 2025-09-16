from __future__ import annotations
from pydantic import BaseModel
import subprocess, shlex
from typing import List, Optional

class SandboxConfig(BaseModel):
    dry_run: bool = False
    timeout_sec: float = 2.0
    max_output_bytes: int = 4096

SANDBOX = SandboxConfig()

def configure(dry_run: Optional[bool]=None, timeout_sec: Optional[float]=None, max_output_bytes: Optional[int]=None):
    global SANDBOX
    data = SANDBOX.model_dump()
    if dry_run is not None:
        data['dry_run'] = dry_run
    if timeout_sec is not None:
        data['timeout_sec'] = timeout_sec
    if max_output_bytes is not None:
        data['max_output_bytes'] = max_output_bytes
    SANDBOX = SandboxConfig(**data)
    return SANDBOX

def run_command(cmd: List[str]) -> dict:
    cfg = SANDBOX
    if cfg.dry_run:
        return {"dry_run": True, "cmd": cmd}
    try:
        raw = subprocess.check_output(cmd, timeout=cfg.timeout_sec, stderr=subprocess.STDOUT)
        truncated = False
        if len(raw) > cfg.max_output_bytes:
            raw = raw[:cfg.max_output_bytes]
            truncated = True
        out = raw.decode(errors='replace').strip()
        return {"output": out, "truncated": truncated}
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    except FileNotFoundError:
        return {"error": "not_found"}
    except Exception as e:
        return {"error": str(e)[:200]}
