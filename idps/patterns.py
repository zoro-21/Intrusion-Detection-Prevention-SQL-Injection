import re

# Common SQL injection tokens and patterns (illustrative, not exhaustive)
RAW_PATTERNS = [
    r"''\s*OR\s*'1'='1",
    r"'\s*OR\s*1=1",
    r"--|#|/\*|\*/",                 # SQL comments
    r";\s*DROP\s+TABLE",
    r"UNION\s+SELECT",
    r"INSERT\s+INTO",
    r"UPDATE\s+\w+\s+SET",
    r"DELETE\s+FROM",
    r"EXEC(UTE)?\s+\w+",
    r"xp_cmdshell",
    r"SLEEP\s*\(\s*\d+\s*\)",
    r"WAITFOR\s+DELAY",
]

COMPILED = [re.compile(p, re.IGNORECASE) for p in RAW_PATTERNS]
