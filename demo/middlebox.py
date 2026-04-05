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
        self.rules = {b"attackat": None}

    def setup_inspection(self):
        # Fixed demo parameters (must match sender exactly)
        g = crypto.get_generator()
        order = crypto.order
        a = 123456789 % order
        b = 987654321 % order
        s = 555555555 % order
        r = 111111111 % order
        R = crypto.exp(crypto.exp(crypto.exp(g, a), b), s)
        R = crypto.exp(R, r)
        k_s1 = 222222222 % order
        k_s2 = 333333333 % order
        k_r = b"fixed_seed_for_demo"
        initial_salt = int.from_bytes(hashlib.sha256(k_r).digest()[:8], 'big')
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
                print("[MB] No data received")
                sender_sock.send(b"ERROR: no data")
                return
            if len(data) < 4:
                print("[MB] Data too short")
                sender_sock.send(b"ERROR: invalid packet")
                return
            num_tokens = struct.unpack('!I', data[:4])[0]
            token_data = data[4:]
            token_size = 32
            if len(token_data) != num_tokens * token_size:
                print(f"[MB] Token data length mismatch: {len(token_data)} vs {num_tokens*token_size}")
                sender_sock.send(b"ERROR: token length mismatch")
                return
            print(f"[MB] Received {num_tokens} encrypted tokens")
            encrypted_tokens = [token_data[i:i+token_size] for i in range(0, num_tokens*token_size, token_size)]
            malicious = False
            for idx, token_ct in enumerate(encrypted_tokens):
                match = traffic_inspection.inspect_token(token_ct)
                if match:
                    print(f"[MB] MALICIOUS token at index {idx} matched rule: {match.decode()}")
                    malicious = True
                    break
            if malicious:
                print(f"[MB] DROPPING malicious traffic")
                sender_sock.send(b"BLOCKED")
            else:
                print(f"[MB] Traffic benign – forwarding to receiver")
                try:
                    receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    receiver_sock.settimeout(3)
                    receiver_sock.connect((self.dest_host, self.dest_port))
                    receiver_sock.send(token_data)
                    receiver_sock.close()
                    sender_sock.send(b"FORWARDED")
                except Exception as e:
                    print(f"[MB] Forwarding failed: {e}")
                    sender_sock.send(b"FORWARD_FAILED")
        except Exception as e:
            print(f"[MB] Exception in handle_sender: {e}")
            import traceback
            traceback.print_exc()
            try:
                sender_sock.send(b"INTERNAL_ERROR")
            except:
                pass
        finally:
            sender_sock.close()

if __name__ == "__main__":
    mb = PrivBoxMiddlebox()
    try:
        mb.start()
    except KeyboardInterrupt:
        print("\n[MB] Shutting down")