#!/usr/bin/env python3
import socket
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.crypto import crypto
from src.core.tokenization import token_encryption

class PrivBoxReceiver:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.sock = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print(f"[Receiver] Listening on {self.host}:{self.port}")
        while True:
            conn, addr = self.sock.accept()
            print(f"[Receiver] Connection from {addr}")
            data = conn.recv(4096)
            if data:
                print(f"[Receiver] Received {len(data)} bytes (simulated decrypted payload)")
                # In real system, decrypt with k_ssl, but for demo just show length
                print(f"[Receiver] Content preview: {data[:50]}...")
            conn.close()

if __name__ == "__main__":
    r = PrivBoxReceiver()
    try:
        r.start()
    except KeyboardInterrupt:
        print("\n[Receiver] Shutting down")