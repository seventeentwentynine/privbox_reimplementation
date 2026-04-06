"""
inspection.py

Implements the highly efficient Traffic Inspection logic for the Middlebox.
Maintains the internal count table (CT_m) to resist token frequency analysis.
"""

from typing import Dict, Any, List
from crypto import H4


class TrafficInspector:
    def __init__(self, session_rules: List[Any], salt: int):
        """
        Initializes the Fast Search Tree (hash map) with the initial state
        of the encrypted rules based on the synchronized salt.
        """
        self.salt = salt
        self.session_rules = session_rules  # Stores the adapted I_i values
        self.count_table: Dict[int, int] = {i: 0 for i in range(len(session_rules))}
        self.search_tree: Dict[bytes, int] = {}

        self._rebuild_search_tree()

    def _rebuild_search_tree(self) -> None:
        """Precomputes and populates the dictionary mapping E_ri -> rule index."""
        self.search_tree.clear()
        for i, I_i in enumerate(self.session_rules):
            count = self.count_table[i]
            # E_ri = H4(S_salt + count, I_i)
            E_ri = H4(self.salt + count, I_i)
            self.search_tree[E_ri] = i

    def inspect_token(self, D_ti: bytes) -> bool:
        """
        Evaluates incoming token D_ti in O(1) time complexity.
        If a match is established, the internal count for that signature
        is incremented, and the search tree node is rebuilt to track the next occurrence.
        """
        if D_ti in self.search_tree:
            rule_index = self.search_tree

            # Action logic triggered here (e.g., alert administrator, drop packet)
            print(f" Critical Signature Match Identified. Rule Index: {rule_index}")

            # Update state sequentially
            self.count_table[rule_index] += 1

            del self.search_tree
            new_count = self.count_table[rule_index]
            new_E_ri = H4(self.salt + new_count, self.session_rules[rule_index])
            self.search_tree[new_E_ri] = rule_index

            return True

        return False