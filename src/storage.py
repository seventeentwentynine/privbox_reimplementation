from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List


@dataclass(frozen=True)
class SignedValue:
    value: Any
    sig_rg: bytes
    sig_mb: bytes


@dataclass(frozen=True)
class RuleTuple:
    R_i: Any
    tilde_R_i: SignedValue
    hat_R_i: SignedValue


@dataclass(frozen=True)
class SetupState:
    y: Any
    y_tilde: Any
    R: SignedValue
    rule_tuples: List[RuleTuple]
