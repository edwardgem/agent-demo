"""
CLI client demonstrating:
- Generating a DPoP keypair (ES256) and storing in client/dpop_keys.json
- Logging in to obtain a JWT access token bound to the DPoP key (cnf.jkt)
- Sending a payment request with DPoP proof
- Handling step-up: either simulated WebAuthn signature or password-based
"""
import json, os, time, uuid, base64, argparse
import httpx
import getpass
from typing import Dict, Any, Optional
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

def _canon_amount(amount: float) -> str:
    return f"{float(amount):.2f}"

def sign_stepup(priv_pem: bytes, sub: str, amount: float, nonce: str) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    msg_amt = _canon_amount(amount)  # <- canonicalize here
    message = f"stepup:{sub}:{msg_amt}:{nonce}".encode()
    sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    return b64url(sig)

# New: helper to set a demo password for password-based step-up

def set_demo_password(sub: str, password: str):
    r = httpx.post(f"{API}/auth/set-password", json={"sub": sub, "password": password}, timeout=10)
    r.raise_for_status()
    return r.json()

# New: check if a user has a password set

def has_password(sub: str) -> bool:
    try:
        r = httpx.get(f"{API}/auth/has-password", params={"sub": sub}, timeout=5)
        r.raise_for_status()
        return r.json().get("has_password", False)
    except Exception:
        return False

# Updated: support both methods and include X-StepUp-Method header

def call_payment(token: str, priv_pem: bytes, sub: str, amount: float, currency: str, payee_id: str, memo: str,
                 method: str = None, password: Optional[str] = None):
    # Always check if password is set for sub and force password step-up if so
    use_password_stepup = sub and has_password(sub)
    print(f"DEBUG: has_password({sub}) = {use_password_stepup}")
    if use_password_stepup:
        method = "password"
    elif sub:
        method = method or "webauthn"
    url = f"{API}/agent/payment"
    proof = dpop_proof(priv_pem, "POST", url)
    headers = {"Authorization": f"Bearer {token}", "DPoP": proof}
    if sub and method:
        headers["X-StepUp-Method"] = method
    r = httpx.post(url, json={"amount": amount, "currency": currency, "payee_id": payee_id, "memo": memo}, headers=headers, timeout=20)
    if r.status_code == 401 and r.json().get("error") == "step_up_required":
        data = r.json()
        if "challenge" not in data and "challenge_error" in data:
            # Backend could not issue a challenge (e.g., sub not registered). Prompt for sub/password and retry.
            print("Step-up required, but no registered user. Please enter sub (username):")
            new_sub = input().strip()
            print(f"Please enter password for user '{new_sub}':")
            new_password = getpass.getpass()
            # Mint new token for new_sub
            keys = ensure_keys()
            new_token = mint_token(sub=new_sub, scopes="agent:payment.initiate", public_jwk=keys["public_jwk"])
            # Recursive retry with new sub/password
            return call_payment(new_token, keys["private_key_pem"].encode(), sub=new_sub, amount=amount, currency=currency, payee_id=payee_id, memo=memo, password=new_password)
        nonce = data["challenge"]["nonce"]
        # If password is set for sub, always use password step-up
        if use_password_stepup:
            proof2 = dpop_proof(priv_pem, "POST", url)
            if not password:
                print(f"Step-up required for user '{sub}'. Please enter password:")
                password = getpass.getpass()
            headers2 = {
                "Authorization": f"Bearer {token}",
                "DPoP": proof2,
                "X-StepUp-Method": "password",
                "X-StepUp-Nonce": nonce,
                "X-StepUp-Signature": password,  # plaintext password for demo only
            }
        else:
            meth = (data.get("method") or method or "webauthn").lower()
            proof2 = dpop_proof(priv_pem, "POST", url)
            # Prompt for sub if missing
            if not sub:
                sub = input("Step-up required. Please enter sub (username): ").strip()
            if meth == "password":
                if not password:
                    print(f"Step-up required for user '{sub}'. Please enter password:")
                    password = getpass.getpass()
                headers2 = {
                    "Authorization": f"Bearer {token}",
                    "DPoP": proof2,
                    "X-StepUp-Method": "password",
                    "X-StepUp-Nonce": nonce,
                    "X-StepUp-Signature": password,
                }
            else:
                signature = sign_stepup(priv_pem, sub=sub, amount=amount, nonce=nonce)
                headers2 = {
                    "Authorization": f"Bearer {token}",
                    "DPoP": proof2,
                    "X-StepUp-Method": "webauthn",
                    "X-StepUp-Nonce": nonce,
                    "X-StepUp-Signature": signature,
                }
        r2 = httpx.post(url, json={"amount": amount, "currency": currency, "payee_id": payee_id, "memo": memo}, headers=headers2, timeout=20)
        print("Response (after step-up):", r2.status_code, r2.json())
    else:
        print("Response:", r.status_code, r.json())

# Remove scenario_low and scenario_high, introduce scenario_payment

def scenario_payment(sub: str = None, password: str = None, amount: float = None):
    # Do not prompt for sub; just pass None if not provided
    if amount is None:
        amount = float(input("Enter payment amount: ").strip())
    keys = ensure_keys()
    token = mint_token(sub=sub, scopes="agent:payment.initiate", public_jwk=keys["public_jwk"])
    call_payment(token, keys["private_key_pem"].encode(), sub=sub, amount=amount, currency="USD", payee_id="vendor-123", memo="Demo payment", password=password)

def scenario_noscope(sub: str = None, password: str = None):
    if not sub:
        sub = "guest"
    keys = ensure_keys()
    token = mint_token(sub=sub, scopes="profile openid", public_jwk=keys["public_jwk"])
    call_payment(token, keys["private_key_pem"].encode(), sub=sub, amount=100, currency="USD", payee_id="vendor-789", memo="Should be denied", password=password)

def scenario_replay(sub: str = None, password: str = None):
    if not sub:
        sub = input("Enter sub (username): ").strip()
    keys1 = ensure_keys()
    token = mint_token(sub=sub, scopes="agent:payment.initiate", public_jwk=keys1["public_jwk"])
    from cryptography.hazmat.primitives.asymmetric import ec
    priv2 = ec.generate_private_key(ec.SECP256R1())
    priv2_pem = priv2.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    url = f"{API}/agent/payment"
    def dpop_with(priv_pem: bytes):
        return dpop_proof(priv_pem, "POST", url)
    import httpx
    r = httpx.post(url,
                   json={"amount": 100, "currency": "USD", "payee_id": "vendor-123", "memo": "replay attempt"},
                   headers={"Authorization": f"Bearer {token}", "DPoP": dpop_with(priv2_pem), "X-StepUp-Method": "webauthn"},
                   timeout=20)
    print("Replay attempt response (expected 401):", r.status_code, r.text)

# New: set password scenario

def scenario_set_password(sub: str = None, password: str = None):
    if not sub:
        sub = input("Enter sub (username): ").strip()
    if not password:
        raise SystemExit("--password is required for set_password scenario")
    res = set_demo_password(sub, password)
    print("Password set:", res)

# Remove CLI entrypoint for scenarios

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["payment", "noscope", "replay", "set_password"], help="Scenario to run")
    parser.add_argument("--amount", nargs="?", type=float, const=None, default=None, help="Payment amount (for 'payment' scenario). If omitted or no value, will prompt.")
    parser.add_argument("--sub", default=None, help="User sub (username)")
    parser.add_argument("--password", default=None, help="Password for step-up (if required)")
    args = parser.parse_args()
    if args.scenario == "set_password":
        scenario_set_password(args.sub, args.password)
    elif args.scenario == "payment":
        amt = args.amount
        if amt is None:
            try:
                amt_input = input("Enter payment amount: ").strip()
                amt = float(amt_input)
            except Exception:
                raise SystemExit("Amount is required for payment scenario.")
        scenario_payment(args.sub, args.password, amt)
    else:
        scenario_noscope(args.sub, args.password) if args.scenario == "noscope" else scenario_replay(args.sub, args.password)
