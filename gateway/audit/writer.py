"""
Append-only audit log with hash chaining.
Each record stores: timestamp, actor, action, inputs hash, decision, and previous hash.
"""
import os, json, hashlib, time
from typing import Dict, Any

AUDIT_FILE = os.path.join(os.path.dirname(__file__), "audit.log")

def _hash_record(rec: Dict[str, Any]) -> str:
    data = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(data).hexdigest()

def _last_hash() -> str:
    if not os.path.exists(AUDIT_FILE):
        return "0"*64
    last = "0"*64
    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                last = json.loads(line.strip())["current_hash"]
            except Exception:
                pass
    return last or "0"*64

def write_audit(actor: str, action: str, inputs: Dict[str, Any], decision: Dict[str, Any], extra: Dict[str, Any] = None) -> str:
    now = int(time.time())
    prev_hash = _last_hash()
    record = {
        "ts": now,
        "actor": actor,
        "action": action,
        "inputs_hash": _hash_record(inputs),
        "decision": decision,
        "prev_hash": prev_hash,
    }
    if extra:
        record["extra"] = extra
    record["current_hash"] = _hash_record(record)
    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
    return record["current_hash"]
