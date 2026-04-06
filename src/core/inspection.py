"""
inspection.py
"""
from typing import Dict, Any, List
from crypto import H4

class TrafficInspector:
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

    def inspect_token(self, D_ti: bytes) -> bool:
        if D_ti in self.search_tree:
            rule_index = self.search_tree[D_ti] # Fixed dictionary lookup

            print(f"[*] Critical Signature Match Identified. Rule Index: {rule_index}")

            self.count_table[rule_index] += 1
            del self.search_tree[D_ti]          # Fixed dictionary key deletion

            new_count = self.count_table[rule_index]
            new_E_ri = H4(self.salt + new_count, self.session_rules[rule_index])
            self.search_tree[new_E_ri] = rule_index

            return True
        return False