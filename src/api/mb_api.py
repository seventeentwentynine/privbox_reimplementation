from fastapi import FastAPI, APIRouter, HTTPException
from typing import Dict, Any
import base64
import hashlib
import os

from .models import Session, EncryptedToken, RuleTuple
from src.core.crypto import crypto
from src.core.tokenization import token_encryption
from src.core.inspection import traffic_inspection

router = APIRouter()
app = FastAPI(title="Middlebox API")

class MiddleboxState:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.rules: Dict[str, Any] = {}
        self.search_tree = {}
        
mb_state = MiddleboxState()


def _demo_params():
    order = crypto.order
    a = 123456789 % order
    b = 987654321 % order
    s = 555555555 % order
    r = 111111111 % order
    g = crypto.get_generator()

    R = crypto.exp(crypto.exp(crypto.exp(g, a), b), s)
    R = crypto.exp(R, r)

    k_s1 = 222222222 % order
    k_s2 = 333333333 % order
    k_r = b"fixed_seed_for_demo"
    initial_salt = int.from_bytes(hashlib.sha256(k_r).digest()[:8], "big")

    return R, k_s1, k_s2, k_r, initial_salt


def _compute_rule_identity(keyword: str):
    R, k_s1, k_s2, _, _ = _demo_params()
    g = crypto.get_generator()
    keyword_bytes = keyword.encode("utf-8")

    h2 = crypto.H2(keyword_bytes)
    R_h2 = crypto.exp(R, h2)
    term1 = crypto.exp(R_h2, k_s1)
    h3 = crypto.H3(R_h2)
    term2 = crypto.exp(g, k_s2 * h3)
    return crypto.mul(term1, term2)


def _decode_token(token_data):
    if isinstance(token_data, dict):
        token_data = token_data.get("ciphertext") or token_data.get("token")
    if isinstance(token_data, str):
        return base64.b64decode(token_data)
    return token_data

@router.post("/session/init")
async def init_session():
    session_id = base64.b64encode(os.urandom(16)).decode()
    session = Session(session_id=session_id)
    mb_state.sessions[session_id] = session
    return {"session_id": session_id}

@router.post("/session/preprocess") # TODO: Verify if preprocessor implementation is done like in the paper
async def run_preprocessing(request: dict):
    session_id = request.get("session_id")
    K_s1 = request.get("K_s1")  # from endpoints
    
    session = mb_state.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Step 1: MB checks if received K_s1 are the same
    # For now, assume single endpoint
    session.k_s1 = base64.b64decode(K_s1) if K_s1 else None
    
    # Step 2: MB sends rule tuples to endpoints
    # For now, return placeholder rule tuples
    rule_tuples = []
    for i, rule in enumerate(mb_state.rules.values()):
        rule_tuples.append({
            "rule_id": rule["rule_id"],
            "R": base64.b64encode(b"placeholder_R").decode(),
            "tilde_R_i": base64.b64encode(f"tilde_{i}".encode()).decode(),
            "hat_R_i": base64.b64encode(f"hat_{i}".encode()).decode()
        })
    
    return {
        "session_id": session_id,
        "rule_tuples": rule_tuples
    }

@router.post("/traffic/inspect")    # TODO: Verify if taffic inspect implementation is done like in the paper
async def inspect_traffic(request: dict):
    """
    Traffic Inspection Phase (Fig. 7 in paper)
    MB receives encrypted tokens and checks for matches
    """
    session_id = request.get("session_id")
    encrypted_tokens = request.get("tokens", [])
    
    matches = []
    blocked = False
    for token_data in encrypted_tokens:
        token_bytes = _decode_token(token_data)
        rule_id = traffic_inspection.inspect_token(token_bytes)
        if rule_id:
            matches.append(rule_id)
            blocked = True
            break
    
    return {
        "session_id": session_id,
        "matches": matches,
        "match_count": len(matches),
        "blocked": blocked,
        "action": "dropped" if blocked else "forwarded",
    }

@router.post("/rules/update")
async def update_rules(rules: dict):
    rule_items = rules.get("rules", rules if isinstance(rules, list) else [])
    if not isinstance(rule_items, list):
        raise HTTPException(status_code=400, detail="rules must be a list")

    demo_rules: Dict[str, Any] = {}
    for item in rule_items:
        keyword = item.get("keyword")
        if not keyword:
            continue
        rule_id = item.get("rule_id") or keyword
        demo_rules[rule_id] = _compute_rule_identity(keyword)

    _, _, _, _, initial_salt = _demo_params()
    mb_state.rules = demo_rules
    traffic_inspection.initialize_session(demo_rules, initial_salt)

    return {
        "message": f"Updated {len(demo_rules)} rules",
        "rules": list(demo_rules.keys()),
        "initial_salt": initial_salt,
    }

app.include_router(router)
