"""
Mock payment worker: "executes" a payment after authorization succeeded.
Returns a fake transaction id.
"""
import uuid, time

def execute_payment(amount: float, currency: str, payee_id: str, memo: str) -> str:
    time.sleep(0.2)
    return f"txn_{uuid.uuid4().hex[:12]}"
