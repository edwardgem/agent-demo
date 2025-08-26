"""
JWT utilities for minting and verifying access tokens (mock OIDC).
Uses ES256 for signing tokens. In production, store keys in KMS/HSM and
publish your JWK Set (/.well-known/jwks.json) for verifiers.
"""
import time, json, base64, hashlib
from typing import Dict, Any
import jwt  # PyJWT
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ISSUER = "https://mock-issuer.local"
AUDIENCE = "payment-agent-gateway"

# Generate a signing key on startup. Replace with persistent KMS-backed key.
_signing_key = ec.generate_private_key(ec.SECP256R1())
_signing_key_pem = _signing_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
_public_key_pem = _signing_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

def _jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    # RFC 7638 JWK thumbprint (base64url) for ES256 public JWK.
    ordered = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    data = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

def mint_access_token(sub: str, scopes: str, public_jwk: Dict[str, Any], ttl_seconds: int = 600) -> str:
    # Mint a short-lived access token (JWT) bound to client's DPoP public key via cnf.jkt.
    now = int(time.time())
    cnf = {"jkt": _jwk_thumbprint(public_jwk)}
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": sub,
        "scope": scopes,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "cnf": cnf,
        "jti": base64.urlsafe_b64encode(hashlib.sha256(f"{sub}.{now}".encode()).digest()).decode().rstrip("="),
    }
    token = jwt.encode(payload, _signing_key_pem, algorithm="ES256", headers={"kid": "demo-kid-1"})
    return token

def verify_access_token(token: str) -> Dict[str, Any]:
    # Verify JWT signature and standard claims.
    payload = jwt.decode(
        token,
        _public_key_pem,
        algorithms=["ES256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"]},
    )
    return payload
