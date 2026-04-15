from __future__ import annotations

from typing import Iterable, List

from config import TOKEN_SIZE


def window_tokenize(data: bytes, token_size: int = TOKEN_SIZE) -> List[bytes]:
    """
    Sliding window tokenization, overlapping tokens.

    If data is shorter than token_size, emit one token = data (if non-empty).
    """
    if token_size <= 0:
        raise ValueError("token_size must be positive")
    if not data:
        return []
    if len(data) < token_size:
        return [data]
    return [data[i : i + token_size] for i in range(0, len(data) - token_size + 1)]


def dedupe_preserve_order(items: Iterable[bytes]) -> List[bytes]:
    seen = set()
    out: List[bytes] = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out
