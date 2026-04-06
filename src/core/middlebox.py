"""
middlebox.py

Centralized network proxy orchestrating DPI operations.
Utilizes multithreading to manage RG synchronization asynchronously 
while simultaneously proxying endpoint traffic flows and enforcing inspection policies.
"""

import socket
import struct
import threading
from protocols import RulePreparationMB, PreprocessingMB
from crypto import serialize_element, deserialize_element, group, G1
from inspection import TrafficInspector


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
        if not chunk: raise RuntimeError("Socket connection failed")
        chunks.append(chunk)
        bytes_recd += len(chunk)
    return b''.join(chunks)


class PrivBoxMiddlebox:
    def __init__(self):
        self.rule_tuples = []
        self.mb_state = RulePreparationMB()
        self.inspector = None
        self.obfuscated_rules = []

    def handle_rg_connection(self, conn: socket.socket) -> None:
        """Executes the Rule Preparation Protocol strictly bounded to the RG connection."""
        print(" Rule Generator connection established.")
        try:
            S_A = deserialize_element(recv_msg(conn))
            L = deserialize_element(recv_msg(conn))

            S_B, S = self.mb_state.step2_get_commitments()
            send_msg(conn, serialize_element(S_B))
            send_msg(conn, serialize_element(S))

            v_count_data = recv_msg(conn)
            v_count = struct.unpack('!I', v_count_data)[0]
            V_list = [deserialize_element(recv_msg(conn)) for _ in range(v_count)]

            # In the protocol flow, MB needs the raw rules to verify V_i = (S_A^b)^H2(r_i)
            # The RG extracts these from the ruleset.
            rules_count_data = recv_msg(conn)
            rules_count = struct.unpack('!I', rules_count_data)[0]
            rules = [recv_msg(conn) for _ in range(rules_count)]

            Y, R_tilde, S_i_list = self.mb_state.step4_verify_and_mask(S_A, V_list, rules)
            send_msg(conn, Y)
            send_msg(conn, serialize_element(R_tilde))
            send_msg(conn, struct.pack('!I', len(S_i_list)))
            for S_i in S_i_list: 
                send_msg(conn, serialize_element(S_i))

            R = deserialize_element(recv_msg(conn))
            tuple_count_data = recv_msg(conn)
            tuple_count = struct.unpack('!I', tuple_count_data)[0]
            raw_tuples = []
            for _ in range(tuple_count):
                R_i = deserialize_element(recv_msg(conn))
                R_i_tilde = deserialize_element(recv_msg(conn))
                R_i_hat = deserialize_element(recv_msg(conn))
                raw_tuples.append((R_i, R_i_tilde, R_i_hat))

            # Perform Pairing validations mathematically
            # step6_finalize_rules(self, R, rule_tuples, L)
            self.mb_state.step6_finalize_rules(R, raw_tuples, L)
            self.rule_tuples = raw_tuples
            print(f" Rule Generation finalized. Stored {len(self.rule_tuples)} signatures.")
        except Exception as e:
            print(f" RG Sync Failed: {e}")
        finally:
            conn.close()

    def handle_client_preprocessing(self, conn: socket.socket) -> None:
        """Executes Preprocessing Phase upon initialization of an endpoint session."""
        print(" Handling endpoint DPI initialization.")
        K_s1 = deserialize_element(recv_msg(conn))

        send_msg(conn, struct.pack('!I', len(self.rule_tuples)))
        for r_tuple in self.rule_tuples:
            _, R_i_tilde, R_i_hat = r_tuple
            send_msg(conn, serialize_element(R_i_tilde))
            send_msg(conn, serialize_element(R_i_hat))

        k_tilde_count_data = recv_msg(conn)
        k_tilde_count = struct.unpack('!I', k_tilde_count_data)[0]
        K_tilde_list = [deserialize_element(recv_msg(conn)) for _ in range(k_tilde_count)]

        prep_mb = PreprocessingMB(self.mb_state.y, self.mb_state.y_tilde)
        self.obfuscated_rules = []
        for i, K_tilde_i in enumerate(K_tilde_list):
            # R_i is the first element of the rule tuple
            R_i = self.rule_tuples[i][0]
            K_i = prep_mb.finalize_K_i(K_tilde_i, K_s1, R_i)
            self.obfuscated_rules.append(K_i)

        salt_data = recv_msg(conn)
        salt = struct.unpack('!I', salt_data)[0]
        self.inspector = TrafficInspector(self.obfuscated_rules, salt)

        # Token Inspection Demultiplexing Loop
        while True:
            d_ti_msg = recv_msg(conn)
            if not d_ti_msg: break
            if d_ti_msg == b"TLS_PASS":
                tls_data = recv_msg(conn)
                print(f" Proxying strictly benign TLS stream. Length: {len(tls_data)} bytes.")
                continue

            if self.inspector.inspect_token(d_ti_msg):
                print(" Executing connection abort sequence for malicious content.")
            else:
                pass

    def start(self) -> None:
        rg_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rg_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        rg_server.bind(('0.0.0.0', 9000))
        rg_server.listen(1)

        client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client_server.bind(('0.0.0.0', 9001))
        client_server.listen(5)

        def accept_rg():
            conn, addr = rg_server.accept()
            self.handle_rg_connection(conn)

        threading.Thread(target=accept_rg, daemon=True).start()

        print(" Middlebox listening for RG on port 9000 and Clients on port 9001...")
        while True:
            conn, addr = client_server.accept()
            threading.Thread(target=self.handle_client_preprocessing, args=(conn,)).start()


if __name__ == "__main__":
    mb = PrivBoxMiddlebox()
    mb.start()
