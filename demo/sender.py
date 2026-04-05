#!/usr/bin/env python3
import socket
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.crypto import crypto
from src.core.tokenization import token_encryption

class PrivBoxSender:
    def __init__(self, mb_host='localhost', mb_port=8888):
        self.mb_host = mb_host
        self.mb_port = mb_port
        self.token_encryption = token_encryption
        self.setup_crypto()

    def setup_crypto(self):
        # Fixed demo parameters (must match middlebox exactly)
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
        self.token_encryption.initialize_first_session(R, k_s1, k_s2, k_r)
        print("[Sender] Crypto initialized (fixed demo parameters)")

    def send_payload(self, payload: bytes):
        if len(payload) < 8:
            print(f" Payload length {len(payload)} < 8 bytes, no tokens generated. Skipping.")
            return
        print(f"\n SENDING PAYLOAD: {payload.decode()}")
        print("-" * 50)
        encrypted_tokens = self.token_encryption.encrypt_payload(payload)
        print(f"   → Generated {len(encrypted_tokens)} encrypted tokens")
        for i, (D_t, count, offset) in enumerate(encrypted_tokens[:5]):
            print(f"   → Token {offset}: {D_t.hex()[:32]}... (count={count})")
        if len(encrypted_tokens) > 5:
            print(f"   ... and {len(encrypted_tokens)-5} more tokens")

        # Build packet: num_tokens (4 bytes) + token_ciphertexts (each 32 bytes)
        token_ciphertexts = []
        for D_t, count, offset in encrypted_tokens:
            if len(D_t) < 32:
                D_t = D_t + b'\x00' * (32 - len(D_t))
            token_ciphertexts.append(D_t)
        data = struct.pack('!I', len(encrypted_tokens)) + b''.join(token_ciphertexts)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((self.mb_host, self.mb_port))
            sock.sendall(data)
            response = sock.recv(1024)
            print(f"\n  Middlebox response: {response.decode()}")
        except Exception as e:
            print(f"\n  Error: {e}")
        finally:
            sock.close()

def interactive_mode():
    sender = PrivBoxSender()
    print("\nConnected to PrivBox Middlebox at localhost:8888\n")
    print("=" * 60)
    print("PRIVBOX SENDER READY")
    print("=" * 60)
    print("\nCommands:")
    print("  send <message>  - Send a message (must be at least 8 chars)")
    print("  attack          - Send 'User executed attackat command'")
    print("  benign          - Send 'Normal browsing activity'")
    print("  quit            - Exit")
    print("-" * 60)

    while True:
        cmd = input("\n> ").strip()
        if cmd.startswith("send "):
            msg = cmd[5:]
            if len(msg) < 8:
                print("   Message too short (<8 bytes). Please enter at least 8 characters.")
                continue
            sender.send_payload(msg.encode())
        elif cmd == "attack":
            sender.send_payload(b"User executed attackat command")
        elif cmd == "benign":
            sender.send_payload(b"Normal browsing activity")
        elif cmd == "quit":
            break
        else:
            print("Unknown command")

if __name__ == "__main__":
    interactive_mode()