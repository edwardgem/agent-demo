"""
Minimal MCP server stub to expose an "initiate_payment" tool.

This is illustrative only. To make it fully functional, adapt to your MCP SDK:
- Acquire a token (call /login/mock-oidc) using your DPoP public JWK
- Call /agent/payment with a DPoP proof
- If step-up is required, sign the challenge with your private key and retry
"""
import os, json, time, base64, uuid
import httpx
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

API = os.environ.get("PAYMENT_API", "http://127.0.0.1:8000")
KEYFILE = os.path.join(os.path.dirname(__file__), "..", "client", "dpop_keys.json")

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def load_keys():
    with open(KEYFILE, "r") as f:
        return json.load(f)

def dpop_proof(priv_pem: bytes, method: str, url: str) -> str:
    import jwt
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pub = priv.public_key()
    pub_nums = pub.public_numbers()
    x = pub_nums.x.to_bytes(32, "big")
    y = pub_nums.y.to_bytes(32, "big")
    jwk = {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y)}
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    claims = {"htm": method.upper(), "htu": url, "iat": int(time.time()), "jti": str(uuid.uuid4())}
    return jwt.encode(claims, priv_pem, algorithm="ES256", headers=headers)

def get_token(sub: str, scopes: str, public_jwk: Dict[str, Any]) -> str:
    r = httpx.post(f"{API}/login/mock-oidc", json={"sub": sub, "scopes": scopes, "public_jwk": public_jwk}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]

def sign_stepup(priv_pem: bytes, sub: str, amount: float, nonce: str) -> str:
    message = f"stepup:{sub}:{amount}:{nonce}".encode()
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return b64url(sig)

def initiate_payment(sub: str, amount: float, currency: str, payee_id: str, memo: str):
    keys = load_keys()
    token = get_token(sub=sub, scopes="agent:payment.initiate", public_jwk=keys["public_jwk"])
    url = f"{API}/agent/payment"
    proof = dpop_proof(keys["private_key_pem"].encode(), "POST", url)
    r = httpx.post(url, json={"amount": amount, "currency": currency, "payee_id": payee_id, "memo": memo},
                   headers={"Authorization": f"Bearer {token}", "DPoP": proof}, timeout=20)
    if r.status_code == 401 and r.json().get("error") == "step_up_required":
        nonce = r.json()["challenge"]["nonce"]
        sig = sign_stepup(keys["private_key_pem"].encode(), sub=sub, amount=amount, nonce=nonce)
        proof2 = dpop_proof(keys["private_key_pem"].encode(), "POST", url)
        r2 = httpx.post(url, json={"amount": amount, "currency": currency, "payee_id": payee_id, "memo": memo},
                        headers={
                            "Authorization": f"Bearer {token}",
                            "DPoP": proof2,
                            "X-StepUp-Nonce": nonce,
                            "X-StepUp-Signature": sig
                        }, timeout=20)
        return r2.status_code, r2.json()
    else:
        return r.status_code, r.json()

if __name__ == "__main__":
    code, resp = initiate_payment(sub="alice", amount=1500, currency="USD", payee_id="vendor-42", memo="MCP test")
    print(code, resp)
