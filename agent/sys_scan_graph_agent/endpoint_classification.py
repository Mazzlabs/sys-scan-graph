from __future__ import annotations
"""Heuristic endpoint (host role) classification.
Derives a coarse host role based on network/routing/containerization signals.
Roles (ordered by specificity):
  bastion: multiple listening sshd + high inbound exposure (many listening services) but little routing.
  lightweight_router: ip_forward enabled OR routing/nat tags present, limited userland services.
  container_host: presence of container-related kernel modules plus docker/containerd sockets.
  dev_workstation: many userland network services (e.g., high ports, web frameworks) AND build/toolchain processes.
  workstation: default fallback when interactive indicators present but nothing else.
Signals consumed from existing findings metadata & tags so we avoid extra system calls.
"""
from typing import List, Tuple
from . import models
Report = models.Report
Finding = models.Finding

ROLE_ORDER = [
    "bastion",
    "lightweight_router",
    "container_host",
    "dev_workstation",
    "workstation",
]

def classify(report: Report) -> Tuple[str, List[str]]:
    if not report or not report.results:
        return "workstation", ["no findings => default workstation"]
    signals: List[str] = []
    counts = {
        'listening_total': 0,
        'listening_ssh': 0,
        'routing': 0,
        'nat': 0,
        'container_mod': 0,
        'dev_ports': 0,
        'high_ports': 0,
        'ip_forward_enabled': 0,
    }
    # Scan findings for signals
    for sr in report.results:
        for f in sr.findings:
            md = f.metadata or {}
            tags = set(f.tags or [])
            if sr.scanner.lower() == 'network' and md.get('state') == 'LISTEN':
                counts['listening_total'] += 1
                port = md.get('port') or md.get('lport')
                if str(port) == '22':
                    counts['listening_ssh'] += 1
                if isinstance(port, int) and port and port >= 30000:
                    counts['high_ports'] += 1
            if 'routing' in tags:
                counts['routing'] += 1
            if 'nat' in tags:
                counts['nat'] += 1
            if sr.scanner.lower() in {'modules','kernel_modules'} and any(t.startswith('container') or 'docker' in (md.get('module') or '') for t in tags.union({md.get('module','')})):
                counts['container_mod'] += 1
            if sr.scanner.lower() == 'kernel_params' and md.get('sysctl_key') == 'net.ipv4.ip_forward' and md.get('value') in {'1','true','on'}:
                counts['ip_forward_enabled'] += 1
            if sr.scanner.lower() == 'network' and md.get('port') in {3000,8000,8080,5000,5173}:
                counts['dev_ports'] += 1
    # Role decision tree
    # lightweight_router if ip_forward or routing/nat and not many userland services
    if counts['ip_forward_enabled'] or (counts['routing'] + counts['nat'] >= 1):
        # If also many listening ssh maybe bastion instead
        if counts['listening_ssh'] >= 2 and counts['listening_total'] <= 6:
            role = 'bastion'
            signals.append(f"bastion: {counts['listening_ssh']} ssh listeners + routing/nat signals")
        else:
            role = 'lightweight_router'
            signals.append("lightweight_router: routing/nat or ip_forward enabled")
        if counts['listening_total'] > 12:
            signals.append(f"{counts['listening_total']} listening services (mixed)")
        return role, signals
    # container host
    if counts['container_mod'] >= 1:
        role = 'container_host'
        signals.append(f"container modules detected ({counts['container_mod']})")
        return role, signals
    # dev workstation
    if counts['dev_ports'] >= 2 and counts['high_ports'] >= 2:
        role = 'dev_workstation'
        signals.append(f"dev ports {counts['dev_ports']} & high ephemeral listeners {counts['high_ports']}")
        return role, signals
    # generic workstation (fallback if some listeners or none)
    role = 'workstation'
    signals.append('default workstation fallback')
    return role, signals
