# agent-payment

This demo shows how a human user safely triggers a Payment Agent using:

- OIDC-like login (local mock) issuing short-lived JWT access tokens with OAuth scopes
- DPoP token binding (Proof-of-Possession) to prevent token replay
- Simulated WebAuthn step-up for high-risk payments (>= threshold)
- Externalized policy (simple, OPA-style logic in Python) to decide allow/deny/step-up
- Immutable audit log with hash chaining (non-repudiation)
- (Optional) MCP server stub so Claude MCP can call the agent as a tool

Note: WebAuthn is simulated here for CLI convenience by signing the server's challenge
using the client's DPoP private key. In production you'd prompt a real WebAuthn assertion.

## Demo scenarios

- Low-risk payment (no step-up): $100 succeeds with scope + DPoP
- High-risk payment (step-up): $1,000+ requires step-up and then succeeds. >$10,000 exceed Max, reject
- Replay attempt: copying the token without the DPoP private key fails
- Scope enforcement: request without `agent:payment.initiate` fails

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

uvicorn gateway.main:app --reload --port 8000

# In another terminal:
python client/app_cli.py payment --amount 100      # $100 (no step-up)
python client/app_cli.py payment --amount 1000     # $1,000 (requires step-up)
python client/app_cli.py                           # will ask user to enter amount
python client/app_cli.py noscope                   # missing scope -> 403
python client/app_cli.py replay                    # token replay attempt -> fails
python client/app_cli.py set_password --sub user_123 --password pw123    # set and remember sub/password pair
```
