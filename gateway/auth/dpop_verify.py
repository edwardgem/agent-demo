"""
Minimal DPoP proof verification for demo purposes.

Validates:
- The DPoP proof JWT header typ is "dpop+jwt" and signature uses ES256
- Claims include htm (HTTP method), htu (HTTP URI), iat (freshness), jti (unique)
- The proof key thumbprint matches the access token's cnf.jkt (token binding)
"""
import time, json, base64, hashlib, urllib.parse
from typing import Dict, Any, Tuple
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from jwt import InvalidTokenError

_seen_jti = set()  # basic replay cache

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")

def jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    ordered = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    data = json.dumps(ordered, separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(data).digest()
    return _b64url(digest)

def verify_dpop_proof(dpop_jwt: str, method: str, url: str, expected_jkt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    # Read header to extract public JWK
    try:
        headers = jwt.get_unverified_header(dpop_jwt)
    except Exception as e:
        raise InvalidTokenError(f"invalid dpop header: {e}")
    if headers.get("typ") != "dpop+jwt":
        raise InvalidTokenError("typ must be dpop+jwt")
    jwk = headers.get("jwk")
    if not jwk:
        raise InvalidTokenError("missing jwk in dpop header")

    # Verify signature using header.jwk
    pub_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(base64.urlsafe_b64decode(jwk["x"] + "=="), "big"),
        int.from_bytes(base64.urlsafe_b64decode(jwk["y"] + "=="), "big"),
        ec.SECP256R1(),
    )
    pubkey = pub_numbers.public_key()
    pub_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    claims = jwt.decode(dpop_jwt, pub_pem, algorithms=["ES256"], options={"require": ["iat", "htu", "htm", "jti"]})

    # Freshness and binding checks
    htm = claims["htm"].upper()
    htu = claims["htu"]
    iat = int(claims["iat"])
    jti = claims["jti"]
    now = int(time.time())
    if abs(now - iat) > 300:
        raise InvalidTokenError("dpop too old/new")
    if htm != method.upper():
        raise InvalidTokenError("method mismatch")
    p_htu = urllib.parse.urlsplit(htu)
    p_url = urllib.parse.urlsplit(url)
    if (p_htu.scheme, p_htu.netloc, p_htu.path) != (p_url.scheme, p_url.netloc, p_url.path):
        raise InvalidTokenError("htu mismatch")
    if jti in _seen_jti:
        raise InvalidTokenError("dpop jti replay")
    _seen_jti.add(jti)

    if jwk_thumbprint(jwk) != expected_jkt:
        raise InvalidTokenError("cnf.jkt mismatch")
    return claims, jwk
