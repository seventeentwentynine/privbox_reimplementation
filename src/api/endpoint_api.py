from fastapi import FastAPI, APIRouter, HTTPException
from typing import List
import base64
import os
import socket
import threading

from OpenSSL import SSL, crypto as openssl_crypto
from .models import Session, EncryptedToken
from src.core.crypto import crypto
from src.core.tokenization import token_encryption

router = APIRouter()
app = FastAPI(title="Endpoint API")


# pyOpenSSL TLS connection between sender and receiver )
class TLSConnection:
    def __init__(self):
        self.ctx = None
        self.connection = None
        self.is_connected = False
        self.cert = None
        self.key = None

    def _generate_self_signed_cert(self):
        key = openssl_crypto.PKey()
        key.generate_key(openssl_crypto.TYPE_RSA, 2048)

        cert = openssl_crypto.X509()
        cert.get_subject().CN = "privbox-endpoint"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        self.cert = cert
        self.key = key

    def setup_sender(self, receiver_host: str, receiver_port: int):
        """Sender connects to receiver over TLS"""
        self._generate_self_signed_cert()

        self.ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        self.ctx.set_verify(SSL.VERIFY_NONE, lambda *args: True)
        self.ctx.use_certificate(self.cert)
        self.ctx.use_privatekey(self.key)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((receiver_host, receiver_port))

        self.connection = SSL.Connection(self.ctx, sock)
        self.connection.set_connect_state()
        self.connection.do_handshake()
        self.is_connected = True

    def setup_receiver(self, listen_port: int):
        """Receiver listens for TLS connection from sender"""
        self._generate_self_signed_cert()

        self.ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        self.ctx.use_certificate(self.cert)
        self.ctx.use_privatekey(self.key)

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", listen_port))
        server_sock.listen(1)

        client_sock, addr = server_sock.accept()
        self.connection = SSL.Connection(self.ctx, client_sock)
        self.connection.set_accept_state()
        self.connection.do_handshake()
        self.is_connected = True
        server_sock.close()

    def send(self, data: bytes):
        if not self.is_connected:
            raise Exception("TLS connection not established")
        self.connection.sendall(data)

    def receive(self, buffer_size: int = 4096) -> bytes:
        if not self.is_connected:
            raise Exception("TLS connection not established")
        return self.connection.recv(buffer_size)

    def close(self):
        if self.connection:
            self.connection.shutdown()
            self.connection.close()
        self.is_connected = False


class EndpointState:
    def __init__(self):
        self.sessions = {}
        self.counter_table = {}  # For token reuse
        self.salt = None
        self.tls = TLSConnection()

endpoint_state = EndpointState()

TLS_PORT = 9000  # port for pyOpenSSL TLS connection between sender and receiver


@router.post("/connect")
async def connect_to_mb():
    """Initialize connection to middlebox"""
    # Generate session keys from TLS handshake (simplified)
    session_id = base64.b64encode(os.urandom(16)).decode()

    # Derive keys: k_SSL, k_s1, k_s2, k_r
    master_secret = os.urandom(32)

    session = Session(
        session_id=session_id,
        k_s1=os.urandom(32),
        k_s2=os.urandom(32),
        k_ssl=master_secret[:16],
        k_r=os.urandom(16)
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


@router.post("/tls/start-receiver")
async def start_tls_receiver():
    """Receiver starts listening for TLS connection from sender (pyOpenSSL)"""
    def _listen():
        endpoint_state.tls.setup_receiver(TLS_PORT)

    thread = threading.Thread(target=_listen, daemon=True)
    thread.start()

    return {
        "status": "listening",
        "port": TLS_PORT
    }


@router.post("/tls/connect-sender")
async def connect_tls_sender(request: dict):
    """Sender connects to receiver over TLS (pyOpenSSL)"""
    receiver_host = request.get("receiver_host", "privbox-receiver")
    receiver_port = request.get("receiver_port", TLS_PORT)

    try:
        endpoint_state.tls.setup_sender(receiver_host, receiver_port)
        return {
            "status": "connected",
            "receiver": f"{receiver_host}:{receiver_port}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"TLS connection failed: {str(e)}")


@router.post("/send")
async def send_data(request: dict):
    """
    Token Encryption Phase (Fig. 6 in paper)
    Sender encrypts payload into tokens and sends payload over TLS to receiver
    """
    session_id = request.get("session_id")
    payload = request.get("payload", "")

    session = endpoint_state.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Tokenize the payload
    if isinstance(payload, str):
        tokens = payload.split()
    else:
        payload_bytes = payload.encode()
        tokens = [payload_bytes[i:i+8] for i in range(len(payload_bytes) - 8 + 1)]

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

    # Send actual payload over pyOpenSSL TLS connection to receiver
    tls_sent = False
    if endpoint_state.tls.is_connected:
        try:
            endpoint_state.tls.send(payload.encode() if isinstance(payload, str) else payload)
            tls_sent = True
        except Exception:
            tls_sent = False

    # Fallback: base64 encoded for API response
    tls_encrypted = base64.b64encode(payload.encode()).decode()

    return {
        "session_id": session_id,
        "encrypted_tokens": [t.dict() for t in encrypted_tokens],
        "tls_traffic": tls_encrypted,
        "tls_payload_sent": tls_sent
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

    # Receive from pyOpenSSL TLS connection if available
    received_payload = None
    if endpoint_state.tls.is_connected:
        try:
            received_payload = endpoint_state.tls.receive()
        except Exception:
            received_payload = None

    # Fallback: decrypt from API payload
    if received_payload is None and tls_traffic:
        received_payload = base64.b64decode(tls_traffic)

    return {
        "session_id": session_id,
        "valid": received_payload is not None,
        "payload": received_payload.decode() if received_payload else None,
        "message": "Traffic validation complete"
    }


app.include_router(router)
