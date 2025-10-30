import re
from .patterns import COMPILED

SAFE_LEN = 128  # simplistic threshold
QUOTE_LIMIT = 4 # excessive quotes often indicate injection attempts

def init_patterns():
    return COMPILED

def _basic_anomaly_checks(s: str):
    reasons = []
    if len(s) > SAFE_LEN:
        reasons.append(f"input too long ({len(s)} chars)")
    # Count quotes & special characters
    quote_count = s.count("'") + s.count('"')
    if quote_count > QUOTE_LIMIT:
        reasons.append(f"excessive quotes ({quote_count})")
    # Heuristic: suspicious mix of operators/keywords
    if any(tok in s.lower() for tok in [" or ", " and ", " union ", " select ", " drop ", " delete ", " insert ", " update ", " exec "]):
        reasons.append("contains SQL keywords/operators in user input")
    return reasons

def _pattern_matches(s: str, compiled_patterns):
    hits = []
    for pat in compiled_patterns:
        if pat.search(s):
            hits.append(pat.pattern)
    return hits

def inspect_input(s: str, compiled_patterns, context: str = ""):
    s = s or ""
    reasons = []
    hits = _pattern_matches(s, compiled_patterns)
    if hits:
        reasons.append("matched SQLi patterns: " + ", ".join(hits))
    reasons.extend(_basic_anomaly_checks(s))

    malicious = len(hits) > 0 or any("input too long" in r or "excessive quotes" in r for r in reasons)
    return {"malicious": malicious, "reasons": reasons}
