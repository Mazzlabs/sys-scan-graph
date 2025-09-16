from __future__ import annotations
"""Load and apply external knowledge dictionaries (ports, modules, suid programs)."""
from pathlib import Path
import yaml
from typing import Dict, Any
import os
import ipaddress

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"
_CACHE: Dict[str, Any] = {}
# Legacy hash tracking placeholder (tests expect attribute)
_HASHES: Dict[str, str] = {}

def _load_yaml(name: str) -> dict:
    if name in _CACHE:
        return _CACHE[name]
    path = KNOWLEDGE_DIR / name
    if not path.exists():
        _CACHE[name] = {}
        return {}
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception:
        data = {}
    _CACHE[name] = data
    return data

def enrich_finding(finding, scanner: str, distro: str):
    # Network ports
    # Normalize network port field name
    if scanner.lower() == "network":
        if 'port' not in finding.metadata and finding.metadata.get('lport'):
            try:
                finding.metadata['port'] = int(finding.metadata.get('lport')) if str(finding.metadata.get('lport')).isdigit() else finding.metadata.get('lport')
            except Exception:
                finding.metadata['port'] = finding.metadata.get('lport')
    if scanner.lower() == "network" and finding.metadata.get("port"):
        ports = _load_yaml("ports.yaml").get("ports", {})
        port_key = str(finding.metadata.get("port"))
        info = ports.get(port_key)
        if info:
            tags = info.get("tags", [])
            for t in tags:
                if t not in finding.tags:
                    finding.tags.append(t)
            finding.metadata.setdefault("service_name", info.get("service"))
            finding.metadata.setdefault("privilege_implication", info.get("privilege_implication"))
    # Kernel / modules
    if scanner.lower() in {"modules","kernel_modules"} and finding.metadata.get("module"):
        modules = _load_yaml("modules.yaml").get("modules", {})
        mod = finding.metadata.get("module")
        info = modules.get(mod)
        if info:
            for t in info.get("tags", []):
                if t not in finding.tags:
                    finding.tags.append(t)
            finding.metadata.setdefault("module_family", info.get("family"))
    # SUID
    if scanner.lower() == "suid" and finding.metadata.get("path"):
        suid = _load_yaml("suid_programs.yaml").get("distro_defaults", {})
        distro_map = suid.get(distro, suid.get("generic", {}))
        expected = set(distro_map.get("expected", []))
        unexpected_tag_list = distro_map.get("unexpected_tags", ["suid_unexpected"])
        import os
        base = os.path.basename(finding.metadata.get("path"))
        if base not in expected:
            for t in unexpected_tag_list:
                if t not in finding.tags:
                    finding.tags.append(t)
            finding.metadata.setdefault("suid_expected", False)
        else:
            finding.metadata.setdefault("suid_expected", True)
    # Org attribution for network connections (ESTABLISHED or LISTEN with rip)
    if scanner.lower() == "network":
        rip = finding.metadata.get("rip")
        if rip and rip != "0.0.0.0":
            orgs = _load_yaml("orgs.yaml").get("orgs", {})
            try:
                ip_obj = ipaddress.ip_address(rip)
            except Exception:
                ip_obj = None
            if ip_obj:
                for name, info in orgs.items():
                    for cidr in info.get("cidrs", []):
                        try:
                            net = ipaddress.ip_network(cidr, strict=False)
                        except Exception:
                            continue
                        if ip_obj in net:
                            # apply tags
                            for t in info.get("tags", []):
                                if t not in finding.tags:
                                    finding.tags.append(t)
                            finding.metadata.setdefault("remote_org", name)
                            break
                    if finding.metadata.get("remote_org"):
                        break

def _verify_signature(fname: str, state):
    """Verify GPG signature of knowledge file using gpg --verify."""
    try:
        if not getattr(state, 'agent_warnings', None):
            # Ensure list exists
            try:
                state.agent_warnings = []  # type: ignore[attr-defined]
            except Exception:
                return

        require_sigs = os.getenv('AGENT_KB_REQUIRE_SIGNATURES', '0') == '1'
        pubkey_path = os.getenv('AGENT_KB_PUBKEY')

        if not require_sigs:
            return

        if not pubkey_path or not Path(pubkey_path).exists():
            if require_sigs:
                state.agent_warnings.append({  # type: ignore[attr-defined]
                    'file': fname,
                    'error_type': 'SignatureVerificationFailed',
                    'error': 'AGENT_KB_PUBKEY not set or file does not exist'
                })
            return

        path = KNOWLEDGE_DIR / fname
        if not path.exists():
            return

        sig_path = path.with_suffix(path.suffix + '.sig')
        if not sig_path.exists():
            if require_sigs:
                state.agent_warnings.append({  # type: ignore[attr-defined]
                    'file': fname,
                    'error_type': 'SignatureMissing'
                })
            return

        # Perform actual GPG verification
        import subprocess
        try:
            # Import the public key if not already imported
            import_result = subprocess.run(
                ['gpg', '--import', pubkey_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Verify the signature
            verify_result = subprocess.run(
                ['gpg', '--verify', str(sig_path), str(path)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if verify_result.returncode == 0:
                # Signature verification successful
                return
            else:
                # Signature verification failed
                error_msg = verify_result.stderr.strip() or 'Unknown GPG verification error'
                state.agent_warnings.append({  # type: ignore[attr-defined]
                    'file': fname,
                    'error_type': 'SignatureVerificationFailed',
                    'error': error_msg
                })

        except subprocess.TimeoutExpired:
            state.agent_warnings.append({  # type: ignore[attr-defined]
                'file': fname,
                'error_type': 'SignatureVerificationTimeout',
                'error': 'GPG verification timed out after 30 seconds'
            })
        except FileNotFoundError:
            state.agent_warnings.append({  # type: ignore[attr-defined]
                'file': fname,
                'error_type': 'GPGNotFound',
                'error': 'gpg command not found in PATH'
            })
        except Exception as e:
            state.agent_warnings.append({  # type: ignore[attr-defined]
                'file': fname,
                'error_type': 'SignatureVerificationError',
                'error': f'Unexpected error during GPG verification: {str(e)}'
            })

    except Exception as e:
        # Fallback error handling
        try:
            if hasattr(state, 'agent_warnings'):
                state.agent_warnings.append({  # type: ignore[attr-defined]
                    'file': fname,
                    'error_type': 'SignatureVerificationSetupError',
                    'error': str(e)
                })
        except Exception:
            pass


def apply_external_knowledge(state):
    if not state.report:
        return state
    # Attempt distro detection (placeholder: from meta or host_id pattern)
    distro = getattr(state.report.meta, 'distro', None) or 'generic'
    # Signature verification for known knowledge files (extendable)
    for candidate in ['ports.yaml','modules.yaml','suid_programs.yaml','orgs.yaml']:
        _verify_signature(candidate, state)
    for sr in state.report.results:
        for f in sr.findings:
            enrich_finding(f, sr.scanner, distro)
    return state