from fastapi import FastAPI, APIRouter, HTTPException, Depends
from typing import List, Dict
import base64
import os

from .models import Session, EncryptedToken, RuleTuple
from core.crypto import crypto
from core.tokenization import tokenizer

router = APIRouter()
app = FastAPI(title="Middlebox API")
app.include_router(router)

class MiddleboxState:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.rules: Dict = {}  # rule storage
        self.search_tree = {}  # for fast lookup
        
mb_state = MiddleboxState()

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
    
    session = mb_state.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    matches = []
    for token_data in encrypted_tokens:
        token = EncryptedToken(**token_data)
        
        # Simplified detection: check if token matches any rule
        for rule_id, rule in mb_state.rules.items():
            # In real implementation: E_r = H4(S_salt + count_r, I_i)
            # Compare with D_t = H4(S_salt + count_t, T_i)
            
            # Placeholder match detection
            if token.ciphertext == rule.get("expected_ciphertext"):
                matches.append({
                    "rule_id": rule_id,
                    "token_offset": token.offset
                })
                # Take action (log, block, etc.)
                break
    
    return {
        "session_id": session_id,
        "matches": matches,
        "match_count": len(matches)
    }

@router.post("/rules/update")
async def update_rules(rules: dict):
    mb_state.rules = rules
    # rebuild search tree
    mb_state.search_tree = {}
    for rule_id, rule in rules.items():
        # precompute encrypted rules for fast lookup
        pass
    return {"message": f"Updated {len(rules)} rules"}