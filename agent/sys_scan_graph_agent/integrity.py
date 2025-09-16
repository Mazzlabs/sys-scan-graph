from __future__ import annotations
import base64, hashlib, json
from pathlib import Path
from typing import Optional, Tuple
from nacl import signing, exceptions

SIG_EXT = ".sig"
HASH_EXT = ".sha256"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def generate_keypair(seed: Optional[bytes] = None) -> Tuple[str,str]:
    if seed:
        sk = signing.SigningKey(seed)
    else:
        sk = signing.SigningKey.generate()
    vk = sk.verify_key
    return base64.b64encode(sk.encode()).decode(), base64.b64encode(vk.encode()).decode()


def load_signing_key(b64: str) -> signing.SigningKey:
    return signing.SigningKey(base64.b64decode(b64))


def load_verify_key(b64: str) -> signing.VerifyKey:
    from nacl import signing as _s
    return _s.VerifyKey(base64.b64decode(b64))


def sign_file(path: Path, signing_key_b64: str) -> Tuple[str,str]:
    sk = load_signing_key(signing_key_b64)
    raw = path.read_bytes()
    digest = sha256_file(path)
    sig = sk.sign(raw).signature
    sig_b64 = base64.b64encode(sig).decode()
    # Write detached artifacts
    path.with_suffix(path.suffix + HASH_EXT).write_text(digest + "\n")
    path.with_suffix(path.suffix + SIG_EXT).write_text(sig_b64 + "\n")
    return digest, sig_b64


def verify_file(path: Path, verify_key_b64: str) -> dict:
    digest_expected_path = path.with_suffix(path.suffix + HASH_EXT)
    sig_path = path.with_suffix(path.suffix + SIG_EXT)
    digest_expected = digest_expected_path.read_text().strip() if digest_expected_path.exists() else None
    sig_b64 = sig_path.read_text().strip() if sig_path.exists() else None
    actual_digest = sha256_file(path)
    status = {
        'sha256_actual': actual_digest,
        'sha256_expected': digest_expected,
        'signature_present': bool(sig_b64),
        'digest_match': digest_expected == actual_digest if digest_expected else False,
        'signature_valid': False
    }
    if sig_b64:
        try:
            vk = load_verify_key(verify_key_b64)
            sig = base64.b64decode(sig_b64)
            vk.verify(path.read_bytes(), sig)
            status['signature_valid'] = True
        except exceptions.BadSignatureError:
            status['signature_valid'] = False
        except Exception:
            status['signature_valid'] = False
    return status

