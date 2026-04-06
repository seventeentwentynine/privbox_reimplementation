from datetime import datetime, timezone
from fastapi import FastAPI, APIRouter, HTTPException
from typing import List
import base64
import os

from .models import Session, EncryptedToken
from src.core.crypto import crypto
from src.core.tokenization import token_encryption

router = APIRouter()
app = FastAPI(title="Endpoint API")
app.include_router(router)

class EndpointState:
    def __init__(self):
        self.sessions = {}
        self.counter_table = {}  # For token reuse
        self.salt = None

endpoint_state = EndpointState()

@router.post("/connect")
async def connect_to_mb():
    """Initialize connection to middlebox"""
    # Generate session keys from TLS handshake (simplified)
    session_id = base64.b64encode(os.urandom(16)).decode()
    
    # Derive keys as per paper: k_SSL, k_s1, k_s2, k_r
    master_secret = os.urandom(32)
    
    session = Session(
        session_id=session_id,
        k_s1=os.urandom(32),
        k_s2=os.urandom(32),
        k_ssl=master_secret[:16],
        k_r=os.urandom(16),
        created_at=datetime.now(timezone.utc)
    )
    
    endpoint_state.sessions[session_id] = session
    
    # Generate initial salt from k_r
    endpoint_state.salt = crypto.generate_salt()
    
    # Compute K_s1 = g^{k_s1} for preprocessing
    K_s1 = base64.b64encode(session.k_s1).decode()
    
    return {
        "session_id": session_id,
        "K_s1": K_s1,
        "initial_salt": base64.b64encode(endpoint_state.salt).decode()
    }

@router.post("/send")
async def send_data(request: dict):
    """
    Token Encryption Phase (Fig. 6 in paper)
    Sender encrypts payload into tokens
    """
    session_id = request.get("session_id")
    payload = request.get("payload", "")
    
    session = endpoint_state.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Tokenize the payload
    if isinstance(payload, str):
        tokens = token_encryption.delimiter_based_tokenization(payload)
    else:
        tokens = token_encryption.window_based_tokenization(payload.encode())
    
    encrypted_tokens = []
    
    for token in tokens:
        # Check counter table for token reuse
        token_key = str(token)
        count = endpoint_state.counter_table.get(token_key, 0)
        
        # Compute T_i (session token)
        # In real implementation: T_i = (R)^{H2(t_i)·k_s1} · g^{k_s2·H3(...)}
        
        # For now, simplified:
        token_bytes = token.encode() if isinstance(token, str) else token
        count_bytes = count.to_bytes(4, 'big')
        
        # D_t = H4(S_salt + count, T_i)
        h4_input = endpoint_state.salt + count_bytes + token_bytes
        ciphertext = crypto.hash_to_key(h4_input)
        
        encrypted_tokens.append(EncryptedToken(
            salt=base64.b64encode(endpoint_state.salt).decode(),
            ciphertext=base64.b64encode(ciphertext).decode(),
            offset=0  # Add proper offset in real implementation
        ))
        
        # Update counter
        endpoint_state.counter_table[token_key] = count + 1
    
    # Also send regular TLS traffic (simplified)
    tls_encrypted = base64.b64encode(payload.encode()).decode()
    
    return {
        "session_id": session_id,
        "encrypted_tokens": [t.dict() for t in encrypted_tokens],
        "tls_traffic": tls_encrypted
    }

@router.post("/receive/validate")
async def validate_traffic(request: dict):
    """
    Traffic Validation Phase
    Receiver validates that tokens match the payload
    """
    session_id = request.get("session_id")
    tls_traffic = request.get("tls_traffic")
    received_tokens = request.get("encrypted_tokens", [])
    
    # Decrypt TLS traffic (simplified)
    payload = base64.b64decode(tls_traffic).decode()
    
    # Re-encrypt locally and compare
    # (Same logic as send_data but with local computation)
    
    return {
        "session_id": session_id,
        "valid": True,  # Placeholder
        "message": "Traffic validation complete"
    }

app.include_router(router)
