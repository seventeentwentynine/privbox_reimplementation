import socket
import struct
import OpenSSL
from protocols import PreprocessingEndpoint
from crypto import group, ZR, G1, serialize_element, deserialize_element, H2, H3, H4, G_BASE
from tokenization import tokenize_payload
from typing import Any

def send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack('!I', len(data)) + data)

def recv_msg(sock: socket.socket) -> bytes:
    length_prefix = sock.recv(4)
    if not length_prefix: return b""
    msg_length = struct.unpack('!I', length_prefix)[0]
    chunks = []
    bytes_recd = 0
    while bytes_recd < msg_length:
        chunk = sock.recv(min(msg_length - bytes_recd, 4096))
        if not chunk: raise RuntimeError("Socket failure")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b''.join(chunks)

class SenderState:
    def __init__(self):
        self.CT: dict = {}

    def derive_keys(self, ekm: bytes) -> None:
        self.k_s1 = group.hash(ekm[:16], ZR)
        self.k_s2 = group.hash(ekm[16:32], ZR)
        self.k_SSL = ekm[32:48]
        self.k_r = ekm[48:64]
        self.S_salt = int.from_bytes(self.k_r[:4], 'big')

    def generate_encrypted_token(self, token: bytes, R: Any) -> bytes:
        count = self.CT.get(token, 0)

        T_ti_tilde = R ** H2(token)

        T_ti = (T_ti_tilde ** self.k_s1) * (G_BASE ** (self.k_s2 * H3(T_ti_tilde)))

        D_ti = H4(self.S_salt + count, T_ti)

        self.CT[token] = count + 1

        return D_ti

def run_sender() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 9001))

    ekm_mock = b'\x01' * 64

    state = SenderState()
    state.derive_keys(ekm_mock)

    prep_endpoint = PreprocessingEndpoint(state.k_s1, state.k_s2)
    send_msg(sock, serialize_element(prep_endpoint.K_s1))

    tuple_count = struct.unpack('!I', recv_msg(sock))[0]
    K_tilde_list = []
    for _ in range(tuple_count):
        R_i_tilde = deserialize_element(recv_msg(sock))
        R_i_hat = deserialize_element(recv_msg(sock))
        K_tilde_list.append(prep_endpoint.compute_K_tilde(R_i_tilde, R_i_hat))

    send_msg(sock, struct.pack('!I', len(K_tilde_list)))
    for K_tilde_i in K_tilde_list:
        send_msg(sock, serialize_element(K_tilde_i))

    send_msg(sock, struct.pack('!I', state.S_salt))

    payload = b"GET / HTTP/1.1\r\nHost: server.local\r\nUNION SELECT password FROM admin;\r\n"
    tokens = tokenize_payload(payload)

    R_mock = group.hash(b"PrivBox_R_mock", G1)

    for token in tokens:
        D_ti = state.generate_encrypted_token(token, R_mock)
        send_msg(sock, D_ti)

    send_msg(sock, b"TLS_PASS")
    send_msg(sock, payload)

    sock.close()

if __name__ == "__main__":
    run_sender()