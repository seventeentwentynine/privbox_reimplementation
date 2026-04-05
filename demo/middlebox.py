#!/usr/bin/env python3
import socket
import struct
import threading
import sys
import os
import hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.crypto import crypto
from src.core.tokenization import token_encryption
from src.core.inspection import traffic_inspection

class PrivBoxMiddlebox:
    def __init__(self, listen_host='0.0.0.0', listen_port=8888, dest_host='localhost', dest_port=9999):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.server = None
        self.rules = {b"attackat": None}   # will hold I_i after init

    def setup_inspection(self):
        # Simulate the same parameters as sender (in reality they would come from protocol)
        # For demo we replicate sender's setup to compute I_i for rules
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
        initial_salt = int.from_bytes(hashlib.sha256(k_r).digest()[:8], 'big')
        # For each rule compute I_i
        for rule in self.rules.keys():
            h2 = crypto.H2(rule)
            R_h2 = crypto.exp(R, h2)
            term1 = crypto.exp(R_h2, k_s1)
            h3 = crypto.H3(R_h2)
            term2 = crypto.exp(g, k_s2 * h3)
            I_i = crypto.mul(term1, term2)
            self.rules[rule] = I_i
        traffic_inspection.initialize_session({rule: I_i for rule, I_i in self.rules.items()}, initial_salt)
        print(f"[MB] Inspection initialized with rules: {[r.decode() for r in self.rules.keys()]}")

    def start(self):
        self.setup_inspection()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.listen_host, self.listen_port))
        self.server.listen(5)
        print(f"[MB] Listening on {self.listen_host}:{self.listen_port}")
        print(f"[MB] Forwarding to {self.dest_host}:{self.dest_port}")
        while True:
            client, addr = self.server.accept()
            print(f"\n[MB] Sender connected from {addr}")
            threading.Thread(target=self.handle_sender, args=(client,)).start()

    def handle_sender(self, sender_sock):
        try:
            data = sender_sock.recv(65536)
            if not data:
                return
            # Parse tokens (same format as sender)
            num_tokens = struct.unpack('!I', data[:4])[0]
            token_data = data[4:]
            token_size = 32
            encrypted_tokens = [token_data[i:i+token_size] for i in range(0, num_tokens*token_size, token_size)]
            
            print(f"[MB] Received {num_tokens} encrypted tokens")
            # Inspect each token
            malicious = False
            for idx, token_ct in enumerate(encrypted_tokens):
                match = traffic_inspection.inspect_token(token_ct)
                if match:
                    print(f"[MB] MALICIOUS token at index {idx} matched rule: {match.decode()}")
                    malicious = True
                    # In real system, MB would drop here. For demo, we drop the whole message.
                    break
            if malicious:
                print(f"[MB] DROPPING malicious traffic (not forwarding to receiver)")
                sender_sock.send(b"BLOCKED")
            else:
                print(f"[MB] Traffic benign – forwarding to receiver")
                # Forward to receiver
                receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                receiver_sock.connect((self.dest_host, self.dest_port))
                receiver_sock.send(token_data)  # forward ciphertexts
                receiver_sock.close()
                sender_sock.send(b"FORWARDED")
        except Exception as e:
            print(f"[MB] Error: {e}")
        finally:
            sender_sock.close()

if __name__ == "__main__":
    mb = PrivBoxMiddlebox()
    try:
        mb.start()
    except KeyboardInterrupt:
        print("\n[MB] Shutting down")