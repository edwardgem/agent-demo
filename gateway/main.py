from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import base64

from gateway.auth.jwt_utils import mint_access_token, verify_access_token
from gateway.auth.dpop_verify import verify_dpop_proof
from gateway.policy.policy_engine import decide
from gateway.audit.writer import write_audit
from gateway.auth import webauthn_flow, password_stepup
from agent.payment_worker import execute_payment

app = FastAPI(title="Payment Agent Gateway (Demo)")

class LoginRequest(BaseModel):
    sub: Optional[str] = None
    scopes: str = "agent:payment.initiate"
    public_jwk: Dict[str, Any]

class PaymentRequest(BaseModel):
    amount: float
    currency: str = "USD"
    payee_id: str
    memo: str = ""

# New: request model for setting a demo password
class SetPasswordRequest(BaseModel):
    sub: str
    password: str

@app.post("/login/mock-oidc")
def login(req: LoginRequest):
    sub = req.sub or "guest"
    token = mint_access_token(sub=sub, scopes=req.scopes, public_jwk=req.public_jwk, ttl_seconds=600)
    return {"access_token": token, "token_type": "Bearer", "expires_in": 600}

# New: demo-only endpoint to set a user's password for step-up
@app.post("/auth/set-password")
def set_password_endpoint(req: SetPasswordRequest):
    try:
        password_stepup.set_password(req.sub, req.password)
        return {"ok": True}
    except ValueError as e:
        msg = str(e)
        if "at least 8 characters" in msg:
            msg = "Password must be at least 8 characters long. Please choose a longer password."
        elif "sub is required" in msg:
            msg = "Username (sub) is required."
        raise HTTPException(status_code=400, detail=msg)

@app.post("/agent/payment")
async def payment(request: Request, body: PaymentRequest,
                  authorization: Optional[str] = Header(None),
                  dpop: Optional[str] = Header(None),
                  x_stepup_nonce: Optional[str] = Header(None),
                  x_stepup_signature: Optional[str] = Header(None),
                  x_stepup_method: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail="missing_bearer_token")
    token = authorization.split(" ", 1)[1]

    try:
        claims = verify_access_token(token)
    except Exception as e:
        raise HTTPException(401, detail=f"invalid_token: {e}")

    if not dpop:
        raise HTTPException(401, detail="missing_dpop_proof")

    url = str(request.url)
    method = request.method

    try:
        dpop_claims, dpop_jwk = verify_dpop_proof(dpop, method, url, expected_jkt=claims.get("cnf", {}).get("jkt", ""))
    except Exception as e:
        raise HTTPException(401, detail=f"invalid_dpop: {e}")

    input_doc = {
        "user": {"sub": claims["sub"]},
        "scopes": claims.get("scope", ""),
        "amount": body.amount,
        "currency": body.currency,
        "payee_id": body.payee_id,
    }
    decision = decide(input_doc)

    # Initialize step-up metadata to avoid UnboundLocalError when not required
    stepup_meta = None

    # --- ENFORCE: sub must be registered ONLY if step-up is required or sub is not 'guest' ---
    sub = claims["sub"]
    # Only enforce registration for step-up or non-guest users
    if sub != "guest":
        if not password_stepup.has_password(sub):
            # If sub is not in _creds at all, fail
            if sub not in password_stepup._creds:
                raise HTTPException(401, detail="sub_not_registered")
            # If sub is in _creds but has no password, allow webauthn

    if decision["result"] == "deny":
        write_audit(actor=claims["sub"], action="payment.initiate", inputs=input_doc, decision=decision)
        raise HTTPException(403, detail=decision)

    if decision["result"] == "require_step_up":
        # Choose step-up method: 'password' (new) or 'webauthn' (existing simulation)
        chosen = (x_stepup_method or "password").lower()
        if chosen not in ("password", "webauthn"):
            chosen = "password"

        if not (x_stepup_nonce and x_stepup_signature):
            if chosen == "password":
                # Issue a password step-up challenge
                try:
                    challenge = password_stepup.new_challenge(sub=claims["sub"])
                except ValueError as e:
                    return JSONResponse(status_code=401, content={
                        "error": "step_up_required",
                        "method": "password",
                        "challenge_error": str(e)
                    })
                return JSONResponse(status_code=401, content={
                    "error": "step_up_required",
                    "method": "password",
                    "challenge": challenge
                })
            else:
                # Build a PEM from DPoP public JWK and issue WebAuthn-like challenge
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import serialization
                pub_numbers = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(base64.urlsafe_b64decode(dpop_jwk["x"] + "=="), "big"),
                    int.from_bytes(base64.urlsafe_b64decode(dpop_jwk["y"] + "=="), "big"),
                    ec.SECP256R1(),
                )
                pubkey = pub_numbers.public_key()
                pub_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                challenge = webauthn_flow.new_challenge(sub=claims["sub"], amount=body.amount, pubkey_pem=pub_pem)
                return JSONResponse(status_code=401, content={
                    "error": "step_up_required",
                    "method": "webauthn",
                    "challenge": challenge
                })
        else:
            if chosen == "password":
                ok = password_stepup.verify_assertion(nonce=x_stepup_nonce, password=x_stepup_signature)
            else:
                ok = webauthn_flow.verify_assertion(nonce=x_stepup_nonce, signature_b64=x_stepup_signature)
            if not ok:
                raise HTTPException(401, detail="step_up_verification_failed")
            stepup_meta = {
                "method": "password" if chosen == "password" else "webauthn_sim",
                "nonce": x_stepup_nonce,
                "result": "verified"
            }

    txn_id = execute_payment(amount=body.amount, currency=body.currency, payee_id=body.payee_id, memo=body.memo)

    # Add token binding + step-up details into the audit 'extra' field
    audit_extra = {
        "txn_id": txn_id,
        "token_jti": claims.get("jti"),
        "cnf_jkt": claims.get("cnf", {}).get("jkt"),  # DPoP key thumbprint (token binding)
    }
    if stepup_meta:
        audit_extra["step_up"] = stepup_meta

    audit_hash = write_audit(
        actor=claims["sub"],
        action="payment.initiate",
        inputs=input_doc,
        decision=decision,
        extra=audit_extra
    )

    return {"status": "ok", "txn_id": txn_id, "audit_hash": audit_hash, "policy": decision}

@app.get("/healthz")
def healthz():
    return {"ok": True}

@app.get("/auth/has-password")
def has_password_endpoint(sub: str):
    return {"has_password": password_stepup.has_password(sub)}
