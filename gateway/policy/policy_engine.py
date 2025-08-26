"""
Simple policy engine that mimics OPA behavior.

Decisions:
- deny if amount > 10000
- require_step_up if amount >= 1000
- allow otherwise

In a real setup, you'd POST inputs to OPA and use its decision.
"""
from typing import Dict, Any

def decide(input_doc: Dict[str, Any]) -> Dict[str, Any]:
    amount = float(input_doc.get("amount", 0))
    scopes = set((input_doc.get("scopes") or "").split())

    if "agent:payment.initiate" not in scopes:
        return {"result": "deny", "reason": "missing_scope_agent:payment.initiate"}
    if amount > 10000:
        return {"result": "deny", "reason": "amount_exceeds_max"}
    if amount >= 1000:
        return {"result": "require_step_up", "reason": "amount_over_threshold"}
    return {"result": "allow", "reason": "ok"}
