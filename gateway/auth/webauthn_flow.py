"""
Simulated WebAuthn step-up:
- Server issues a random challenge tied to user+amount.
- Client signs it with its DPoP private key (for demo only).
- Server verifies signature using the DPoP public key from the DPoP proof / token binding.
"""
import os, time, base64
from typing import Dict, Any
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

_pending = {}


def _canon_amount(amount: float) -> str:
    # Always render amounts as 2 decimal places to avoid "5000" vs "5000.0" mismatch
    return f"{float(amount):.2f}"

def new_challenge(sub: str, amount: float, pubkey_pem: bytes) -> Dict[str, Any]:
    nonce = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    _pending[nonce] = {
        "sub": sub,
        "amount": _canon_amount(amount),          # <- store canonical string
        "exp": int(time.time()) + 180,            # <- give 2 minutes to respond
        "pubkey_pem": pubkey_pem.decode()
    }
    return {"nonce": nonce, "prompt": f"Confirm payment of {_pending[nonce]['amount']} by {sub}"}

def verify_assertion(nonce: str, signature_b64: str) -> bool:
    entry = _pending.get(nonce)
    if not entry:
        return False
    if int(time.time()) > entry["exp"]:
        _pending.pop(nonce, None)
        return False
    pubkey = serialization.load_pem_public_key(entry["pubkey_pem"].encode())
    # Build the exact same message string we expect the client to sign:
    message = f"stepup:{entry['sub']}:{entry['amount']}:{nonce}".encode()
    try:
        pubkey.verify(base64.urlsafe_b64decode(signature_b64 + "=="), message, ec.ECDSA(hashes.SHA256()))
        _pending.pop(nonce, None)
        return True
    except InvalidSignature:
        return False
