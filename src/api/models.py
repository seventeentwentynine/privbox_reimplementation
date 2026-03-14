from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

# Define structure of API requests/responses.
# Rule-related models
class Rule(BaseModel):
    rule_id: str
    keyword: str  # For Protocol I, start with single keywords
    signature: Optional[str] = None

class RuleSet(BaseModel):
    rules: List[Rule]
    timestamp: datetime = Field(default_factory=datetime.now)

# Protocol messages
class RuleTuple(BaseModel):
    """The rule tuple (R̂_i, Sig_RG(R̂_i), Sig_MB(R̂_i), etc.)"""
    R: str  # Base64 encoded group element
    signature_rg: str
    signature_mb: str
    tilde_R_i: str
    hat_R_i: str

class PreprocessingRequest(BaseModel):
    session_id: str
    K_s1: str  # g^{k_s1}
    
class EncryptedToken(BaseModel):
    salt: str
    ciphertext: str
    offset: Optional[int] = None

# Session management
class Session(BaseModel):
    session_id: str
    created_at: datetime
    k_s1: Optional[bytes] = None
    k_s2: Optional[bytes] = None
    k_ssl: Optional[bytes] = None
    k_r: Optional[bytes] = None