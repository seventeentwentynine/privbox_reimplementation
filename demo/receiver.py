#!/usr/bin/env python3
import socket

class PrivBoxReceiver:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        print(f"[Receiver] Listening on {self.host}:{self.port}")
        while True:
            conn, addr = sock.accept()
            print(f"[Receiver] Connection from {addr}")
            data = conn.recv(4096)
            if data:
                print(f"[Receiver] Received {len(data)} bytes (encrypted tokens)")
                print(f"[Receiver] First 32 bytes: {data[:32].hex()}")
            conn.close()

if __name__ == "__main__":
    r = PrivBoxReceiver()
    try:
        r.start()
    except KeyboardInterrupt:
        print("\n[Receiver] Shutting down")