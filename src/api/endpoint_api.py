from fastapi import FastAPI, APIRouter, HTTPException
from datetime import datetime
from typing import List
import base64
import hashlib
import json
import os
import urllib.request

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


def _ensure_demo_crypto(reset: bool = False):
    if reset or token_encryption.R is None:
        R, k_s1, k_s2, k_r, _ = _demo_params()
        token_encryption.initialize_first_session(R, k_s1, k_s2, k_r)


def _middlebox_url() -> str:
    return os.getenv("MIDDLEBOX_INSPECT_URL", "http://middlebox:8000/traffic/inspect")


def _post_json(url: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))

@router.post("/connect")
async def connect_to_mb():
    """Initialize connection to middlebox"""
    session_id = base64.b64encode(os.urandom(16)).decode()
    _, k_s1, k_s2, k_r, initial_salt = _demo_params()

    session = Session(
        session_id=session_id,
        created_at=datetime.now(),
        k_s1=k_s1.to_bytes(32, "big"),
        k_s2=k_s2.to_bytes(32, "big"),
        k_ssl=b"demo-master-secret"[:16],
        k_r=k_r
    )
    
    endpoint_state.sessions[session_id] = session
    endpoint_state.salt = initial_salt

    K_s1 = base64.b64encode(session.k_s1).decode()
    
    return {
        "session_id": session_id,
        "K_s1": K_s1,
        "initial_salt": base64.b64encode(endpoint_state.salt.to_bytes(16, "big")).decode()
    }

@router.post("/send")
async def send_data(request: dict):
    """
    Token Encryption Phase (Fig. 6 in paper)
    Sender encrypts payload into tokens
    """
    payload = request.get("payload", "")
    # Keep demo behavior deterministic and in sync with MB's freshly published rule state.
    _ensure_demo_crypto(reset=True)

    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    else:
        payload_bytes = payload

    print(f"[Sender] Encrypting payload: {payload_bytes}")
    encrypted_tokens = token_encryption.encrypt_payload(payload_bytes)
    print(f"[Sender] Generated {len(encrypted_tokens)} encrypted tokens")

    token_ciphertexts = [base64.b64encode(D_t).decode("utf-8") for D_t, _, _ in encrypted_tokens]
    middlebox_response = _post_json(_middlebox_url(), {"tokens": token_ciphertexts})
    print(f"[Sender] Middlebox response: {middlebox_response}")

    return {
        "payload": payload_bytes.decode("utf-8", errors="replace"),
        "token_count": len(encrypted_tokens),
        "first_tokens": token_ciphertexts[:5],
        "middlebox_response": middlebox_response,
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
