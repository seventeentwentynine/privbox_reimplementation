#!/usr/bin/env python3
"""
PrivBox Sender - Encrypts traffic and sends to middlebox
Run this in a separate terminal
"""

import socket
import struct
import sys
import os
import time
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.crypto import crypto
from src.core.tokenization import token_encryption

class PrivBoxSender:
    def __init__(self, server_host='localhost', server_port=8888):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.token_encryption = token_encryption
        
    def connect(self):
        """Connect to middlebox"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.server_host, self.server_port))
        print(f"🔗 Connected to PrivBox Middlebox at {self.server_host}:{self.server_port}")
        
    def setup_crypto(self):
        """Initialize crypto (would get R from MB in real system)"""
        print("\n Initializing sender crypto...")
        
        # In real system, these come from protocols
        a = crypto.random_scalar()
        b = crypto.random_scalar()
        s = crypto.random_scalar()
        r = crypto.random_scalar()
        g = crypto.get_generator()
        
        R = crypto.exp(crypto.exp(crypto.exp(g, a), b), s)
        R = crypto.exp(R, r)
        
        k_s1 = crypto.random_scalar()
        k_s2 = crypto.random_scalar()
        k_r = crypto.random_bytes(16)
        
        self.token_encryption.initialize_first_session(R, k_s1, k_s2, k_r)
        print(f"Token encryption initialized")
        
    def send_payload(self, payload: bytes):
        """Encrypt and send a payload"""
        print(f"\n SENDING PAYLOAD: {payload.decode()}")
        print("-" * 50)
        
        # Encrypt the payload
        encrypted_tokens = self.token_encryption.encrypt_payload(payload)
        
        print(f"   → Generated {len(encrypted_tokens)} encrypted tokens")
        
        # Prepare data: [num_tokens (4 bytes)] + [tokens]
        token_ciphertexts = []
        for D_t, count, offset in encrypted_tokens:
            # Ensure D_t is 32 bytes (pad if needed)
            if len(D_t) < 32:
                D_t = D_t + b'\x00' * (32 - len(D_t))
            token_ciphertexts.append(D_t)
            print(f"   → Token {offset}: {D_t.hex()[:32]}... (count={count})")
        
        data = struct.pack('!I', len(encrypted_tokens)) + b''.join(token_ciphertexts)
        
        # Send
        self.socket.send(data)
        
        # Receive confirmation
        response = self.socket.recv(1024)
        print(f"\n  Middlebox response: {response.decode()}")
        
        return encrypted_tokens
    
    def close(self):
        """Close connection"""
        if self.socket:
            self.socket.close()

def interactive_mode():
    """Interactive mode for live demo"""
    sender = PrivBoxSender()
    sender.connect()
    sender.setup_crypto()
    
    print("\n" + "=" * 60)
    print("PRIVBOX SENDER READY")
    print("=" * 60)
    print("\nCommands:")
    print("  send <message>  - Send a message")
    print("  attack          - Send malicious test message")
    print("  benign          - Send benign test message")
    print("  quit            - Exit")
    print("-" * 60)
    
    while True:
        cmd = input("\n> ").strip()
        
        if cmd.startswith("send "):
            msg = cmd[5:]
            sender.send_payload(msg.encode())
            
        elif cmd == "attack":
            sender.send_payload(b"User executed attackat command")
            
        elif cmd == "benign":
            sender.send_payload(b"Normal browsing activity")
            
        elif cmd == "quit":
            break
        else:
            print("Unknown command")
    
    sender.close()

if __name__ == "__main__":
    interactive_mode()