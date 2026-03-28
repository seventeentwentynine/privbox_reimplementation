from fastapi import FastAPI, APIRouter, HTTPException, Depends
from typing import List
import base64
import json
import os

from .models import Rule, RuleSet, RuleTuple
from core.crypto import crypto

router = APIRouter()
app = FastAPI(title="Rule Generator API")
app.include_router(router)

# simple in-memory storage for now
class RuleStorage:
    def __init__(self):
        self.rules = []
        self.rule_tuples = {}
        
    def load_snort_rules(self, filepath: str):
        # load Snort rules from a file
        import re
        rules = []
        with open(filepath, 'r') as f:
            for line in f:                    
                content_match = re.search(r'content:"([^"]+)"', line)
                if content_match:
                    rule_id = f"rule_{len(rules)}"
                    keyword = content_match.group(1)
                    rules.append(Rule(rule_id=rule_id, keyword=keyword))
        self.rules = rules
        return rules

rule_storage = RuleStorage()

@router.get("/rules", response_model=List[Rule])
async def get_rules():
    return rule_storage.rules

@router.post("/rules/prepare")
async def prepare_rules_with_mb(mb_public_key: str):
    """
    Step 1 of Rule Preparation Protocol (Fig. 2 in paper)
    RG computes S_A = g^a, L = g^r and sends to MB
    """
    # TODO: Verify if this implementation is how its done in the paper
    # Generate RG's secrets
    a = int.from_bytes(os.urandom(32), 'big')
    r = int.from_bytes(os.urandom(32), 'big')
    
    # Store secrets for this session
    rg_session = {
        'a': a,
        'r': r,
        'mb_public_key': mb_public_key
    }
    
    # Compute S_A = g^a, L = g^r
    # For now, just return placeholders - you'll implement actual EC operations later
    S_A = base64.b64encode(b"placeholder_S_A").decode()
    L = base64.b64encode(b"placeholder_L").decode()
    
    return {
        "S_A": S_A,
        "L": L,
        "session_id": "rg_session_1"
    }

@router.post("/rules/generate-tuples")
async def generate_rule_tuples(request: dict):
    """
    Steps 3-5 of Rule Preparation Protocol
    Generate {V_i} and later rule tuples
    """
    # This will be implemented after basic crypto is working
    pass

# Simple endpoint to load initial rules
@router.post("/rules/load")
async def load_rules():
    """Load sample rules (start with just a few)"""
    sample_rules = [
        Rule(rule_id="1", keyword="attack"),
        Rule(rule_id="2", keyword="malware"),
        Rule(rule_id="3", keyword="exploit"),
        Rule(rule_id="4", keyword="injection"),
        Rule(rule_id="5", keyword="xss")
    ]
    rule_storage.rules = sample_rules
    return {"message": f"Loaded {len(sample_rules)} rules", "rules": sample_rules}