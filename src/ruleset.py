from __future__ import annotations

import re
from typing import List

from config import DEFAULT_RULESET_TEXT
from tokenization import window_tokenize, dedupe_preserve_order

_CONTENT_RE = re.compile(r'content\s*:\s*"(.*?)"\s*;')


def load_ruleset_text(path: str | None = None) -> str:
    if path is None:
        return DEFAULT_RULESET_TEXT
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def extract_rule_tokens(ruleset_text: str) -> List[bytes]:
    """
    Extract rule tokens (rule domain R = {r_i}) as bytes.
    We focus on Snort-like content:...; fields when present.
    """
    tokens: List[bytes] = []
    for line in ruleset_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        m = _CONTENT_RE.findall(line)
        if m:
            for s in m:
                tokens.extend(window_tokenize(s.encode("utf-8")))
        else:
            tokens.extend(window_tokenize(line.encode("utf-8")))
    return dedupe_preserve_order(tokens)
