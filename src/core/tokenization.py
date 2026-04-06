"""
tokenization.py
"""
from typing import List, Set

TOKEN_SIZE = 8
DELIMITERS = {b' ', b',', b'.', b'?', b'=', b'&', b'/', b'\n', b'\r'}

def tokenize_payload(payload: bytes) -> List[bytes]:
    tokens = []
    length = len(payload)

    if length < TOKEN_SIZE:
        return []

    for i in range(length - TOKEN_SIZE + 1):
        window = payload[i:i+TOKEN_SIZE]
        tokens.append(window)

    seen: Set[bytes] = set()
    unique_tokens = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique_tokens.append(t)

    return unique_tokens

def extract_rules(ruleset_text: str) -> List[bytes]:
    rules = []
    for line in ruleset_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line_bytes = line.encode('utf-8')
        rules.extend(tokenize_payload(line_bytes))
    return list(set(rules))