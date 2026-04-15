from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict, List

from crypto import serialize_element, deserialize_element
from storage import SetupState, SignedValue, RuleTuple


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _ser_elem(x: Any) -> str:
    return _b64e(serialize_element(x))


def _deser_elem(s: str) -> Any:
    return deserialize_element(_b64d(s))


def dump_setup_state(state: SetupState) -> Dict[str, Any]:
    return {
        "y": _ser_elem(state.y),
        "y_tilde": _ser_elem(state.y_tilde),
        "R": {
            "value": _ser_elem(state.R.value),
            "sig_rg": _b64e(state.R.sig_rg),
            "sig_mb": _b64e(state.R.sig_mb),
        },
        "rule_tuples": [
            {
                "R_i": _ser_elem(rt.R_i),
                "tilde_R_i": {
                    "value": _ser_elem(rt.tilde_R_i.value),
                    "sig_rg": _b64e(rt.tilde_R_i.sig_rg),
                    "sig_mb": _b64e(rt.tilde_R_i.sig_mb),
                },
                "hat_R_i": {
                    "value": _ser_elem(rt.hat_R_i.value),
                    "sig_rg": _b64e(rt.hat_R_i.sig_rg),
                    "sig_mb": _b64e(rt.hat_R_i.sig_mb),
                },
            }
            for rt in state.rule_tuples
        ],
    }


def load_setup_state(d: Dict[str, Any]) -> SetupState:
    R = d["R"]
    rule_tuples: List[RuleTuple] = []
    for item in d["rule_tuples"]:
        til = item["tilde_R_i"]
        hat = item["hat_R_i"]
        rule_tuples.append(
            RuleTuple(
                R_i=_deser_elem(item["R_i"]),
                tilde_R_i=SignedValue(
                    value=_deser_elem(til["value"]),
                    sig_rg=_b64d(til["sig_rg"]),
                    sig_mb=_b64d(til["sig_mb"]),
                ),
                hat_R_i=SignedValue(
                    value=_deser_elem(hat["value"]),
                    sig_rg=_b64d(hat["sig_rg"]),
                    sig_mb=_b64d(hat["sig_mb"]),
                ),
            )
        )

    return SetupState(
        y=_deser_elem(d["y"]),
        y_tilde=_deser_elem(d["y_tilde"]),
        R=SignedValue(
            value=_deser_elem(R["value"]),
            sig_rg=_b64d(R["sig_rg"]),
            sig_mb=_b64d(R["sig_mb"]),
        ),
        rule_tuples=rule_tuples,
    )


def save_setup_state(path: Path, state: SetupState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(dump_setup_state(state), indent=2), encoding="utf-8")
    tmp.replace(path)


def try_load_setup_state(path: Path) -> SetupState | None:
    if not path.exists():
        return None
    d = json.loads(path.read_text(encoding="utf-8"))
    return load_setup_state(d)
