"""
rule_generator.py

Network entity implementation for the Rule Generator (RG).
Binds to raw TCP sockets, executing the length-prefixed binary framing protocol
to transmit variables derived from the Rule Preparation Protocol.
"""

import socket
import struct
from protocols import RulePreparationRG
from crypto import serialize_element, deserialize_element
from tokenization import extract_rules


def send_msg(sock: socket.socket, data: bytes) -> None:
    """Applies a 4-byte length prefix to prevent TCP fragmentation issues."""
    length_prefix = struct.pack('!I', len(data))
    sock.sendall(length_prefix + data)


def recv_msg(sock: socket.socket) -> bytes:
    """Consumes the length prefix to accurately rebuild fragmented payloads."""
    length_prefix = sock.recv(4)
    if not length_prefix:
        return b""
    msg_length = struct.unpack('!I', length_prefix)[0]

    chunks = []
    bytes_recd = 0
    while bytes_recd < msg_length:
        chunk = sock.recv(min(msg_length - bytes_recd, 4096))
        if not chunk:
            raise RuntimeError("Socket connection abruptly terminated.")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b''.join(chunks)


def run_rule_generator(mb_host: str, mb_port: int, ruleset_text: str) -> None:
    print(" Extracting and tokenizing ruleset...")
    rules = extract_rules(ruleset_text)
    rg_state = RulePreparationRG(rules)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f" Initiating TCP connection to Middlebox at {mb_host}:{mb_port}")
        sock.connect((mb_host, mb_port))

        # Transmit Commitments
        S_A, L = rg_state.step1_get_commitments()
        send_msg(sock, serialize_element(S_A))
        send_msg(sock, serialize_element(L))

        S_B = deserialize_element(recv_msg(sock))
        S = deserialize_element(recv_msg(sock))

        V_list = rg_state.step3_process_mb_commitments(S_B, S)
        send_msg(sock, struct.pack('!I', len(V_list)))
        for V_i in V_list:
            send_msg(sock, serialize_element(V_i))

        Y = recv_msg(sock)
        R_tilde = deserialize_element(recv_msg(sock))
        s_i_count_data = recv_msg(sock)
        s_i_count = struct.unpack('!I', s_i_count_data)[0]
        S_i_list = [deserialize_element(recv_msg(sock)) for _ in range(s_i_count)]

        R, rule_tuples = rg_state.step5_generate_obfuscated_rules(Y, R_tilde, S_i_list)
        send_msg(sock, serialize_element(R))
        send_msg(sock, struct.pack('!I', len(rule_tuples)))

        for r_tuple in rule_tuples:
            R_i, R_i_tilde, R_i_hat = r_tuple
            send_msg(sock, serialize_element(R_i))
            send_msg(sock, serialize_element(R_i_tilde))
            send_msg(sock, serialize_element(R_i_hat))

        print(" Rule Preparation Protocol successfully concluded.")


if __name__ == "__main__":
    SAMPLE_RULES = "drop tcp any any -> any 80 (msg:\"SQL Injection\"; content:\"UNION SELECT\";)\n"
    run_rule_generator('127.0.0.1', 9000, SAMPLE_RULES)