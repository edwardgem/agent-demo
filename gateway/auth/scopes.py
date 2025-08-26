from typing import Iterable, Set

def parse_scopes(scope_str: str) -> Set[str]:
    return set((scope_str or "").split())

def require_scopes(have: str, need: Iterable[str]) -> bool:
    have_set = parse_scopes(have)
    return all(s in have_set for s in need)
