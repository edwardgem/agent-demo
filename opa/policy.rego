package policy.agent

default decision = {"result": "deny", "reason": "default_deny"}

decision = {"result": "deny", "reason": "missing_scope_agent:payment.initiate"} {
  not input.scopes
} else = {"result": "deny", "reason": "missing_scope_agent:payment.initiate"} {
  not contains(input.scopes, "agent:payment.initiate")
}

decision = {"result": "deny", "reason": "amount_exceeds_max"} {
  input.amount > 10000
}

decision = {"result": "require_step_up", "reason": "amount_over_threshold"} {
  input.amount >= 1000
  contains(input.scopes, "agent:payment.initiate")
}

decision = {"result": "allow", "reason": "ok"} {
  input.amount < 1000
  contains(input.scopes, "agent:payment.initiate")
}

contains(s, needle) {
  some i
  split(s, " ")[i] == needle
}
