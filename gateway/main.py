from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import base64

from gateway.auth.jwt_utils import mint_access_token, verify_access_token
from gateway.auth.dpop_verify import verify_dpop_proof
from gateway.policy.policy_engine import decide
from gateway.audit.writer import write_audit
from gateway.auth import webauthn_flow
from agent.payment_worker import execute_payment

app = FastAPI(title="Payment Agent Gateway (Demo)")

class LoginRequest(BaseModel):
    sub: str
    scopes: str = "agent:payment.initiate"
    public_jwk: Dict[str, Any]

class PaymentRequest(BaseModel):
    amount: float
    currency: str = "USD"
    payee_id: str
    memo: str = ""

@app.post("/login/mock-oidc")
def login(req: LoginRequest):
    token = mint_access_token(sub=req.sub, scopes=req.scopes, public_jwk=req.public_jwk, ttl_seconds=600)
    return {"access_token": token, "token_type": "Bearer", "expires_in": 600}

@app.post("/agent/payment")
async def payment(request: Request, body: PaymentRequest,
                  authorization: Optional[str] = Header(None),
                  dpop: Optional[str] = Header(None),
                  x_stepup_nonce: Optional[str] = Header(None),
                  x_stepup_signature: Optional[str] = Header(None)):
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

    if decision["result"] == "deny":
        write_audit(actor=claims["sub"], action="payment.initiate", inputs=input_doc, decision=decision)
        raise HTTPException(403, detail=decision)

    if decision["result"] == "require_step_up":
        if not (x_stepup_nonce and x_stepup_signature):
            # Build a PEM from DPoP public JWK
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            import base64
            pub_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(base64.urlsafe_b64decode(dpop_jwk["x"] + "=="), "big"),
                int.from_bytes(base64.urlsafe_b64decode(dpop_jwk["y"] + "=="), "big"),
                ec.SECP256R1(),
            )
            pubkey = pub_numbers.public_key()
            pub_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
            challenge = webauthn_flow.new_challenge(sub=claims["sub"], amount=body.amount, pubkey_pem=pub_pem)
            return JSONResponse(status_code=401, content={"error": "step_up_required", "challenge": challenge})
        else:
            ok = webauthn_flow.verify_assertion(nonce=x_stepup_nonce, signature_b64=x_stepup_signature)
            if not ok:
                raise HTTPException(401, detail="step_up_verification_failed")

    txn_id = execute_payment(amount=body.amount, currency=body.currency, payee_id=body.payee_id, memo=body.memo)
    audit_hash = write_audit(actor=claims["sub"], action="payment.initiate", inputs=input_doc, decision=decision, extra={"txn_id": txn_id})
    return {"status": "ok", "txn_id": txn_id, "audit_hash": audit_hash, "policy": decision}

@app.get("/healthz")
def healthz():
    return {"ok": True}
