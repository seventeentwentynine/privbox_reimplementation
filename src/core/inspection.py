# src/core/inspection.py
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from .crypto import crypto

@dataclass
class RuleEntry:
    rule_id: str
    count: int
    E_r: bytes

class TrafficInspection:
    def __init__(self):
        self.search_tree: Dict[bytes, str] = {}
        self.rule_counter: Dict[str, RuleEntry] = {}
        self.session_rules: Dict[str, Any] = {}   # I_i per rule
        self.salt: int = 0

    def initialize_session(self, session_rules: Dict[str, Any], initial_salt: int):
        self.session_rules = session_rules
        self.salt = initial_salt
        self.search_tree.clear()
        self.rule_counter.clear()
        # Precompute E_r for count=0
        for rule_id, I_i in session_rules.items():
            E_r = crypto.H4(self.salt, I_i)
            self.search_tree[E_r] = rule_id
            self.rule_counter[rule_id] = RuleEntry(rule_id, 0, E_r)

    def update_salt(self, new_salt: int):
        self.salt = new_salt
        self._rebuild_tree()

    def _rebuild_tree(self):
        self.search_tree.clear()
        for rule_id, entry in self.rule_counter.items():
            I_i = self.session_rules[rule_id]
            E_r = crypto.H4(self.salt + entry.count, I_i)
            entry.E_r = E_r
            self.search_tree[E_r] = rule_id

    def inspect_token(self, D_t: bytes) -> Optional[str]:
        if D_t in self.search_tree:
            rule_id = self.search_tree[D_t]
            self._handle_match(rule_id)
            return rule_id
        return None

    def inspect_payload(self, encrypted_tokens: List[bytes]) -> List[str]:
        matches = []
        for D_t in encrypted_tokens:
            rule_id = self.inspect_token(D_t)
            if rule_id:
                matches.append(rule_id)
        return matches

    def _handle_match(self, rule_id: str):
        # Step 1.1.1: take action (log, block, etc.)
        print(f"MATCH: rule {rule_id} detected")
        entry = self.rule_counter[rule_id]
        # Remove old node
        del self.search_tree[entry.E_r]
        # Increment count
        entry.count += 1
        # Insert new node
        I_i = self.session_rules[rule_id]
        new_E_r = crypto.H4(self.salt + entry.count, I_i)
        entry.E_r = new_E_r
        self.search_tree[new_E_r] = rule_id

traffic_inspection = TrafficInspection()