"""
CLI client demonstrating:
- Generating a DPoP keypair (ES256) and storing in client/dpop_keys.json
- Logging in to obtain a JWT access token bound to the DPoP key (cnf.jkt)
- Sending a payment request with DPoP proof
- Handling step-up: sign the challenge with the DPoP private key (simulated WebAuthn)
"""
import json, os, time, uuid, base64, argparse
import httpx
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes

API = "http://127.0.0.1:8000"
KEYFILE = os.path.join(os.path.dirname(__file__), "dpop_keys.json")

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def ensure_keys():
    if os.path.exists(KEYFILE):
        with open(KEYFILE, "r") as f:
            data = json.load(f)
        return data
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pub = priv.public_key()
    pub_nums = pub.public_numbers()
    x = pub_nums.x.to_bytes(32, "big")
    y = pub_nums.y.to_bytes(32, "big")
    jwk = {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y)}
    data = {"private_key_pem": priv_pem.decode(), "public_jwk": jwk}
    with open(KEYFILE, "w") as f:
        json.dump(data, f, indent=2)
    return data

def mint_token(sub: str, scopes: str, public_jwk: Dict[str, Any]) -> str:
    r = httpx.post(f"{API}/login/mock-oidc", json={"sub": sub, "scopes": scopes, "public_jwk": public_jwk}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]

def dpop_proof(priv_pem: bytes, method: str, url: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    import jwt
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    pub = priv.public_key()
    pub_nums = pub.public_numbers()
    x = pub_nums.x.to_bytes(32, "big")
    y = pub_nums.y.to_bytes(32, "big")
    jwk = {"kty": "EC", "crv": "P-256", "x": b64url(x), "y": b64url(y)}
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    claims = {"htm": method.upper(), "htu": url, "iat": int(time.time()), "jti": str(uuid.uuid4())}
    token = jwt.encode(claims, priv_pem, algorithm="ES256", headers=headers)
    return token

def sign_stepup(priv_pem: bytes, sub: str, amount: float, nonce: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    message = f"stepup:{sub}:{amount}:{nonce}".encode()
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return b64url(sig)

def call_payment(token: str, priv_pem: bytes, sub: str, amount: float, currency: str, payee_id: str, memo: str):
    url = f"{API}/agent/payment"
    proof = dpop_proof(priv_pem, "POST", url)
    r = httpx.post(url,
                   json={"amount": amount, "currency": currency, "payee_id": payee_id, "memo": memo},
                   headers={"Authorization": f"Bearer {token}", "DPoP": proof},
                   timeout=20)
    if r.status_code == 401 and r.json().get("error") == "step_up_required":
        nonce = r.json()["challenge"]["nonce"]
        signature = sign_stepup(priv_pem, sub=sub, amount=amount, nonce=nonce)
        proof2 = dpop_proof(priv_pem, "POST", url)
        r2 = httpx.post(url,
                        json={"amount": amount, "currency": currency, "payee_id": payee_id, "memo": memo},
                        headers={
                            "Authorization": f"Bearer {token}",
                            "DPoP": proof2,
                            "X-StepUp-Nonce": nonce,
                            "X-StepUp-Signature": signature
                        },
                        timeout=20)
        print("Response (after step-up):", r2.status_code, r2.json())
    else:
        print("Response:", r.status_code, r.json())

def scenario_low():
    keys = ensure_keys()
    token = mint_token(sub="alice", scopes="agent:payment.initiate", public_jwk=keys["public_jwk"])
    call_payment(token, keys["private_key_pem"].encode(), sub="alice", amount=100, currency="USD", payee_id="vendor-123", memo="Office supplies")

def scenario_high():
    keys = ensure_keys()
    token = mint_token(sub="alice", scopes="agent:payment.initiate", public_jwk=keys["public_jwk"])
    call_payment(token, keys["private_key_pem"].encode(), sub="alice", amount=5000, currency="USD", payee_id="vendor-456", memo="Laptop purchase")

def scenario_noscope():
    keys = ensure_keys()
    token = mint_token(sub="alice", scopes="profile openid", public_jwk=keys["public_jwk"])
    call_payment(token, keys["private_key_pem"].encode(), sub="alice", amount=100, currency="USD", payee_id="vendor-789", memo="Should be denied")

def scenario_replay():
    keys1 = ensure_keys()
    token = mint_token(sub="alice", scopes="agent:payment.initiate", public_jwk=keys1["public_jwk"])

    # Attacker with different keypair (token binding should fail)
    from cryptography.hazmat.primitives.asymmetric import ec
    priv2 = ec.generate_private_key(ec.SECP256R1())
    priv2_pem = priv2.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    url = f"{API}/agent/payment"
    def dpop_with(priv_pem: bytes):
        return dpop_proof(priv_pem, "POST", url)

    import httpx
    r = httpx.post(url,
                   json={"amount": 100, "currency": "USD", "payee_id": "vendor-123", "memo": "replay attempt"},
                   headers={"Authorization": f"Bearer {token}", "DPoP": dpop_with(priv2_pem)},
                   timeout=20)
    print("Replay attempt response (expected 401):", r.status_code, r.text)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["low", "high", "noscope", "replay"])
    args = parser.parse_args()
    {"low": scenario_low, "high": scenario_high, "noscope": scenario_noscope, "replay": scenario_replay}[args.scenario]()
