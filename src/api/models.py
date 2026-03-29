from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime

# Define structure of API requests/responses.
# Rule related models which will use the crypto package, need to implement Priv Box Encryption still
class Rule(BaseModel):
    rule_id: str
    keyword: str  # For Protocol I, start with single keywords
    signature: Optional[str] = None

class RuleSet(BaseModel):
    rules: List[Rule]
    timestamp: datetime = Field(default_factory=datetime.now)

# Protocol messages
class RuleTuple(BaseModel):
    """The rule tuple (R^{hat}_i, Sig_RG(R^{hat}_i), Sig_MB(R^{hat}_i), etc.)"""
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
    model_config = ConfigDict(arbitrary_types_allowed=True)
    session_id: str
    created_at: datetime = Field(default_factory=datetime.now)
    k_s1: Optional[bytes] = None
    k_s2: Optional[bytes] = None
    k_ssl: Optional[bytes] = None
    k_r: Optional[bytes] = None
