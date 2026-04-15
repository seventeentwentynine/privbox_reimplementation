from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from crypto import H4


@dataclass(frozen=True)
class Match:
    rule_index: int
    token_position: int


class TrafficInspector:
    """
    Vanilla inspection sketch consistent with Fig. 7-style behavior:
    - precompute per-rule encrypted values E_{r_i} keyed by (salt + count_{r_i})
    - match a ciphertext token by dictionary lookup
    - on match, increment count_{r_i} and rebuild that rule's entry
    """

    def __init__(self, session_rules: List[Any], salt: int):
        self.salt = salt
        self.session_rules = session_rules
        self.count_table: Dict[int, int] = {i: 0 for i in range(len(session_rules))}
        self.search_tree: Dict[bytes, int] = {}
        self._rebuild_search_tree()

    def _rebuild_search_tree(self) -> None:
        self.search_tree.clear()
        for i, I_i in enumerate(self.session_rules):
            count = self.count_table[i]
            E_ri = H4(self.salt + count, I_i)
            self.search_tree[E_ri] = i

    def inspect(self, token_ciphertext: bytes, token_position: int) -> Optional[Match]:
        idx = self.search_tree.get(token_ciphertext)
        if idx is None:
            return None

        # match: increment the rule count and update the entry
        self.count_table[idx] += 1
        I_i = self.session_rules[idx]
        new_E = H4(self.salt + self.count_table[idx], I_i)
        self.search_tree[new_E] = idx

        return Match(rule_index=idx, token_position=token_position)

    # Back-compat alias (some demos call inspect_token)
    def inspect_token(self, token_ciphertext: bytes, token_position: int) -> Optional[Match]:
        return self.inspect(token_ciphertext, token_position)
