from __future__ import annotations

import logging
import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import (
    LOG_DIR,
    MB_ENDPOINT_PORT,
    MB_RULE_PREP_PORT,
    MB_STATE_DIR,
    TLS_PROXY_PORT,
    RECEIVER_HOST,
    RECEIVER_TLS_PORT,
)
from framing import (
    recv_bytes,
    send_bytes,
    recv_element,
    send_element,
    recv_int,
    send_int,
    recv_str,
    send_str,
)
from inspection import TrafficInspector, Match
from key_management import load_private_key, load_public_key
from protocols import RulePreparationMB, RGOutboundFig2Step5, PreprocessingMB, session_rules_first_session
from ruleset import load_ruleset_text, extract_rule_tokens
from state_store import save_setup_state, try_load_setup_state
from storage import SetupState


SETUP_STATE_FILE = Path(MB_STATE_DIR) / "setup_state.json"


def _hex(b: bytes) -> str:
    return b.hex()


@dataclass
class EndpointContribution:
    role: bytes  # b"S" or b"R"
    K_s1: Any
    tildeK_list: List[Any]
    S_salt: int


@dataclass
class SessionContext:
    session_id: bytes
    sender_flow: Optional[Tuple[str, int]] = None  # (ip, port) for relay enforcement
    prep: Dict[bytes, EndpointContribution] = field(default_factory=dict)
    inspector: Optional[TrafficInspector] = None
    token_stream: Optional[List[bytes]] = None
    matches: Optional[List[Match]] = None
    ready: bool = False
    cond: threading.Condition = field(default_factory=lambda: threading.Condition(threading.Lock()))


class RelayRegistry:
    """
    Tracks live MB relay connections keyed by client (ip, port), so MB can close them on DROP.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conns: Dict[Tuple[str, int], socket.socket] = {}

    def register(self, peer: Tuple[str, int], sock: socket.socket) -> None:
        with self._lock:
            self._conns[peer] = sock

    def unregister(self, peer: Tuple[str, int]) -> None:
        with self._lock:
            self._conns.pop(peer, None)

    def close_peer(self, peer: Tuple[str, int]) -> None:
        with self._lock:
            s = self._conns.get(peer)
        if s is None:
            return
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            s.close()
        except Exception:
            pass


class MBServer:
    def __init__(self) -> None:
        Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
        Path(MB_STATE_DIR).mkdir(parents=True, exist_ok=True)

        self.log = logging.getLogger("mb")
        self.log.setLevel(logging.INFO)
        fh = logging.FileHandler(Path(LOG_DIR) / "mb.log")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        self.log.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("[mb] %(message)s"))
        self.log.addHandler(sh)

        self.drop_log_path = Path(LOG_DIR) / "mb_dropped.log"

        # Keys
        self.sk_mb = load_private_key("mb")
        self.pk_rg = load_public_key("rg")

        # Rules (shared with RG for demo)
        self.rules = extract_rule_tokens(load_ruleset_text())

        self.setup_state: Optional[SetupState] = try_load_setup_state(SETUP_STATE_FILE)
        if self.setup_state:
            self.log.info("Loaded SetupState from disk")
        else:
            self.log.info("No SetupState on disk yet. Run RG after MB is up.")

        self.sessions: Dict[bytes, SessionContext] = {}
        self.sessions_lock = threading.Lock()

        self.relay = RelayRegistry()

    def get_session(self, session_id: bytes) -> SessionContext:
        with self.sessions_lock:
            ctx = self.sessions.get(session_id)
            if ctx is None:
                ctx = SessionContext(session_id=session_id)
                self.sessions[session_id] = ctx
            return ctx

    def run(self) -> None:
        t1 = threading.Thread(target=self._run_rule_prep_server, daemon=True)
        t2 = threading.Thread(target=self._run_endpoint_server, daemon=True)
        t3 = threading.Thread(target=self._run_tls_relay, daemon=True)
        t1.start()
        t2.start()
        t3.start()
        self.log.info("MB is running: rule_prep=9000, endpoint=9001, tls_relay=8443")
        t1.join()
        t2.join()
        t3.join()

    def _run_rule_prep_server(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", MB_RULE_PREP_PORT))
            srv.listen(5)
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self._handle_rg, args=(conn, addr), daemon=True).start()

    def _handle_rg(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        self.log.info(f"RG connected from {addr}")
        try:
            mb = RulePreparationMB(rules=self.rules, sk_sig_mb=self.sk_mb, pk_sig_rg=self.pk_rg)

            # Step 1: receive (S_A, L)
            S_A = recv_element(conn)
            L = recv_element(conn)

            # Step 2: send (S_B, S)
            S_B, S = mb.step2_commitments(S_A, L)
            send_element(conn, S_B)
            send_element(conn, S)

            # Step 3: receive V_list
            n = recv_int(conn)
            V_list = [recv_element(conn) for _ in range(n)]

            # Step 4: send (Y, R_tilde, S_i_list)
            Y, R_tilde, S_i_list = mb.step4_verify_and_mask(V_list)
            send_bytes(conn, Y)
            send_element(conn, R_tilde)
            send_int(conn, len(S_i_list))
            for S_i in S_i_list:
                send_element(conn, S_i)

            # Step 5: receive msg from RG
            R_hat = recv_element(conn)
            sig_rg_R = recv_bytes(conn)
            m = recv_int(conn)
            items = []
            for _ in range(m):
                R_i = recv_element(conn)
                tilde_R_i = recv_element(conn)
                sig_tilde = recv_bytes(conn)
                hat_R_i = recv_element(conn)
                sig_hat = recv_bytes(conn)
                items.append((R_i, tilde_R_i, sig_tilde, hat_R_i, sig_hat))

            msg = RGOutboundFig2Step5(R_hat=R_hat, sig_rg_R=sig_rg_R, items=items)
            state = mb.step6_verify_and_store(msg)

            self.setup_state = state
            save_setup_state(SETUP_STATE_FILE, state)

            send_bytes(conn, b"OK: setup_state stored")
            self.log.info("Rule preparation completed; SetupState persisted")
        except Exception as e:
            self.log.exception("Rule preparation failure")
            try:
                send_bytes(conn, f"ERROR: {e}".encode("utf-8"))
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _run_endpoint_server(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", MB_ENDPOINT_PORT))
            srv.listen(20)
            while True:
                conn, addr = srv.accept()
                threading.Thread(target=self._handle_endpoint, args=(conn, addr), daemon=True).start()

    def _handle_endpoint(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            tag = recv_bytes(conn)
            if not tag:
                return
            if tag == b"PREP_HELLO":
                self._handle_prep(conn)
            elif tag == b"SUBMIT_TOKENS":
                self._handle_submit(conn)
            elif tag == b"GET_TOKENS":
                self._handle_get_tokens(conn)
            else:
                send_bytes(conn, b"ERROR: unknown tag")
        except Exception:
            self.log.exception("endpoint handler crashed")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send_setup(self, conn: socket.socket) -> None:
        if self.setup_state is None:
            send_bytes(conn, b"ERROR: no SetupState on MB; run RG first")
            return
        st = self.setup_state

        send_bytes(conn, b"PREP_SETUP")
        send_int(conn, len(st.rule_tuples))

        # Signed R
        send_element(conn, st.R.value)
        send_bytes(conn, st.R.sig_rg)
        send_bytes(conn, st.R.sig_mb)

        # Rule tuples
        for rt in st.rule_tuples:
            send_element(conn, rt.R_i)

            send_element(conn, rt.tilde_R_i.value)
            send_bytes(conn, rt.tilde_R_i.sig_rg)
            send_bytes(conn, rt.tilde_R_i.sig_mb)

            send_element(conn, rt.hat_R_i.value)
            send_bytes(conn, rt.hat_R_i.sig_rg)
            send_bytes(conn, rt.hat_R_i.sig_mb)

    def _handle_prep(self, conn: socket.socket) -> None:
        if self.setup_state is None:
            send_bytes(conn, b"ERROR: no SetupState on MB; run RG first")
            return

        session_id = recv_bytes(conn)
        role = recv_bytes(conn)  # b"S" or b"R"
        flow_ip = recv_str(conn)
        flow_port = int(recv_int(conn))

        ctx = self.get_session(session_id)
        if role == b"S" and flow_ip and flow_port:
            ctx.sender_flow = (flow_ip, flow_port)

        self._send_setup(conn)

        tag2 = recv_bytes(conn)
        if tag2 != b"PREP_RESPONSE":
            send_bytes(conn, b"ERROR: expected PREP_RESPONSE")
            return

        K_s1 = recv_element(conn)
        n = recv_int(conn)
        tildeK_list = [recv_element(conn) for _ in range(n)]
        S_salt = int(recv_int(conn))

        contrib = EndpointContribution(role=role, K_s1=K_s1, tildeK_list=tildeK_list, S_salt=S_salt)

        with ctx.cond:
            ctx.prep[role] = contrib

            # If both endpoints arrived, finalize the session
            if b"S" in ctx.prep and b"R" in ctx.prep and not ctx.ready:
                cS, cR = ctx.prep[b"S"], ctx.prep[b"R"]
                if cS.K_s1 != cR.K_s1:
                    ctx.ready = False
                    send_bytes(conn, b"PREP_ABORT: mismatch K_s1")
                    ctx.cond.notify_all()
                    return
                if cS.S_salt != cR.S_salt:
                    ctx.ready = False
                    send_bytes(conn, b"PREP_ABORT: mismatch S_salt")
                    ctx.cond.notify_all()
                    return
                if len(cS.tildeK_list) != len(cR.tildeK_list) or any(a != b for a, b in zip(cS.tildeK_list, cR.tildeK_list)):
                    ctx.ready = False
                    send_bytes(conn, b"PREP_ABORT: mismatch tildeK_list")
                    ctx.cond.notify_all()
                    return

                st = self.setup_state
                assert st is not None
                R_i_list = [rt.R_i for rt in st.rule_tuples]
                mb_prep = PreprocessingMB(y=st.y, y_tilde=st.y_tilde)
                K_list = mb_prep.finalize_K(K_s1=cS.K_s1, tildeK_list=cS.tildeK_list, R_i_list=R_i_list)
                I_list = session_rules_first_session(K_list)
                ctx.inspector = TrafficInspector(I_list, cS.S_salt)
                ctx.ready = True
                self.log.info(f"Session ready: {session_id.hex()} rules={len(I_list)}")
                ctx.cond.notify_all()

            # Wait until ready or abort
            deadline = 30.0
            # simple wait without actual timeouts to keep code short
            while not ctx.ready:
                ctx.cond.wait(timeout=1.0)
                deadline -= 1.0
                if deadline <= 0:
                    break

        if ctx.ready:
            send_bytes(conn, b"PREP_DONE")
        else:
            send_bytes(conn, b"PREP_ABORT: timeout waiting for peer")

    def _handle_submit(self, conn: socket.socket) -> None:
        session_id = recv_bytes(conn)
        token_count = int(recv_int(conn))
        tokens = [recv_bytes(conn) for _ in range(token_count)]

        ctx = self.get_session(session_id)
        if not ctx.ready or ctx.inspector is None:
            send_bytes(conn, b"ERROR: session not ready")
            return

        matches: List[Match] = []
        for pos, tok in enumerate(tokens):
            m = ctx.inspector.inspect(tok, pos)
            if m is not None:
                matches.append(m)

        ctx.token_stream = tokens
        ctx.matches = matches

        decision = b"ALLOW" if not matches else b"DROP"

        # Enforcement: close sender relay connection if DROP and flow known
        if decision == b"DROP" and ctx.sender_flow is not None:
            self.relay.close_peer(ctx.sender_flow)

            # Log: allowed metadata only (no TLS plaintext)
            with self.drop_log_path.open("a", encoding="utf-8") as f:
                f.write(
                    f"session={_hex(session_id)} decision=DROP matches="
                    + ",".join(f"(rule={m.rule_index},pos={m.token_position})" for m in matches)
                    + "\n"
                )

        send_bytes(conn, b"DECISION")
        send_bytes(conn, decision)
        send_int(conn, len(matches))
        for m in matches:
            send_int(conn, m.rule_index)
            send_int(conn, m.token_position)

    def _handle_get_tokens(self, conn: socket.socket) -> None:
        session_id = recv_bytes(conn)
        ctx = self.get_session(session_id)
        if ctx.token_stream is None:
            send_bytes(conn, b"TOKEN_STREAM_NOT_READY")
            return
        send_bytes(conn, b"TOKEN_STREAM")
        send_int(conn, len(ctx.token_stream))
        for t in ctx.token_stream:
            send_bytes(conn, t)

    def _run_tls_relay(self) -> None:
        """
        Pure TCP relay: listens on TLS_PROXY_PORT and forwards bytes to receiver:RECEIVER_TLS_PORT.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", TLS_PROXY_PORT))
            srv.listen(50)
            while True:
                client, addr = srv.accept()
                threading.Thread(target=self._relay_one, args=(client, addr), daemon=True).start()

    def _relay_one(self, client: socket.socket, addr: Tuple[str, int]) -> None:
        peer = (addr[0], addr[1])
        self.relay.register(peer, client)
        upstream = None
        try:
            upstream = socket.create_connection((RECEIVER_HOST, RECEIVER_TLS_PORT), timeout=10.0)
            t1 = threading.Thread(target=self._pipe, args=(client, upstream), daemon=True)
            t2 = threading.Thread(target=self._pipe, args=(upstream, client), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception:
            pass
        finally:
            self.relay.unregister(peer)
            try:
                client.close()
            except Exception:
                pass
            if upstream is not None:
                try:
                    upstream.close()
                except Exception:
                    pass

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    MBServer().run()


if __name__ == "__main__":
    main()
