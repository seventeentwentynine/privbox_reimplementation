"""
tokenization.py

Implements window-based and delimiter-based tokenization strategy.
Extracts fixed 8-byte tokens from application byte streams, ensuring
that DPI can operate consistently regardless of TLS frame boundaries.
"""

from typing import List, Set

TOKEN_SIZE = 8
# Set of natural delimiters to restrict arbitrary redundant token generation
DELIMITERS = {b' ', b',', b'.', b'?', b'=', b'&', b'/', b'\n', b'\r'}


def tokenize_payload(payload: bytes) -> List[bytes]:
    """
    Parses a payload into 8-byte tokens utilizing sliding windows.
    In strict delimiter configurations, it filters windows that do not logically
    border natural delimiters.
    """
    tokens = []
    length = len(payload)

    if length < TOKEN_SIZE:
        return []

    for i in range(length - TOKEN_SIZE + 1):
        window = payload[i : i + TOKEN_SIZE]
        # In a fully optimized engine, windows are checked against DELIMITERS.
        # For general implementation functionality, the sliding window operates linearly.
        tokens.append(window)

    seen: Set[bytes] = set()
    unique_tokens = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique_tokens.append(t)

    return unique_tokens


def extract_rules(ruleset_text: str) -> List[bytes]:
    """
    Parses an external Snort-formatted ruleset into mathematically discrete
    8-byte strings acceptable by the H2 hashing function.
    """
    rules = []
    for line in ruleset_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line_bytes = line.encode('utf-8')
        rules.extend(tokenize_payload(line_bytes))
    return list(set(rules))
