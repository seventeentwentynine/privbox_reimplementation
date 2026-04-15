from __future__ import annotations

import argparse
import socket
from pathlib import Path

from config import (
    LOG_DIR,
    MB_HOST,
    MB_ENDPOINT_PORT,
    TLS_PROXY_HOST,
    TLS_PROXY_PORT,
    TLS_SERVER_NAME,
    TLS_EXPORT_LABEL,
    TLS_EXPORT_LEN,
)
from framing import (
    send_bytes,
    recv_bytes,
    send_int,
    recv_int,
    send_element,
    recv_element,
    send_str,
    recv_str,
)
from kdf import derive_endpoint_secrets, session_id_from_exporter
from key_management import load_public_key
from protocols import PreprocessingEndpoint, TokenEncryptor
from ruleset import load_ruleset_text, extract_rule_tokens
from tokenization import window_tokenize
from tls_channel import TLSClient
from http1 import build_http_post


def run_once(payload: str) -> int:
    body = payload.encode("utf-8")

    # TLS connect via MB relay
    tls = TLSClient(server_name=TLS_SERVER_NAME)
    tls_conn, ekm = tls.connect(
        host=TLS_PROXY_HOST,
        port=TLS_PROXY_PORT,
        export_label=TLS_EXPORT_LABEL,
        export_len=TLS_EXPORT_LEN,
    )

    # flow id seen by MB relay (client ip/port)
    local_ip, local_port = tls_conn.tcp.getsockname()[:2]

    session_id = session_id_from_exporter(ekm)
    secrets = derive_endpoint_secrets(ekm)

    pk_rg = load_public_key("rg")
    pk_mb = load_public_key("mb")

    # Preprocessing with MB
    ep = PreprocessingEndpoint(secrets.k_s1, secrets.k_s2, pk_sig_rg=pk_rg, pk_sig_mb=pk_mb)

    with socket.create_connection((MB_HOST, MB_ENDPOINT_PORT), timeout=10.0) as c:
        send_bytes(c, b"PREP_HELLO")
        send_bytes(c, session_id)
        send_bytes(c, b"S")
        send_str(c, str(local_ip))
        send_int(c, int(local_port))

        tag = recv_bytes(c)
        if tag != b"PREP_SETUP":
            err = tag.decode("utf-8", "replace")
            print(f"[sender] MB error: {err}")
            tls_conn.shutdown()
            return 2

        n = recv_int(c)

        # Signed R
        from storage import SignedValue, RuleTuple
        R_val = recv_element(c)
        R_sig_rg = recv_bytes(c)
        R_sig_mb = recv_bytes(c)
        R_signed = SignedValue(value=R_val, sig_rg=R_sig_rg, sig_mb=R_sig_mb)

        rule_tuples = []
        for _ in range(n):
            R_i = recv_element(c)

            t_val = recv_element(c)
            t_sig_rg = recv_bytes(c)
            t_sig_mb = recv_bytes(c)

            h_val = recv_element(c)
            h_sig_rg = recv_bytes(c)
            h_sig_mb = recv_bytes(c)

            rule_tuples.append(
                RuleTuple(
                    R_i=R_i,
                    tilde_R_i=SignedValue(value=t_val, sig_rg=t_sig_rg, sig_mb=t_sig_mb),
                    hat_R_i=SignedValue(value=h_val, sig_rg=h_sig_rg, sig_mb=h_sig_mb),
                )
            )

        tildeK = ep.verify_and_compute_tildeK(R_signed, rule_tuples)

        send_bytes(c, b"PREP_RESPONSE")
        send_element(c, ep.K_s1)
        send_int(c, len(tildeK))
        for x in tildeK:
            send_element(c, x)
        send_int(c, int(secrets.S_salt))

        done = recv_bytes(c)
        if done != b"PREP_DONE":
            print(f"[sender] preprocessing failed: {done.decode('utf-8','replace')}")
            tls_conn.shutdown()
            return 2

    # Token encryption
    if ep.R is None:
        raise RuntimeError("endpoint R missing after preprocessing")
    enc = TokenEncryptor(R=ep.R, k_s1=secrets.k_s1, k_s2=secrets.k_s2, S_salt=secrets.S_salt, K_s=None)
    toks = window_tokenize(body)
    d_toks = [enc.encrypt_token(t) for t in toks]

    # Submit tokens to MB
    decision = b"ERROR"
    matches = []
    with socket.create_connection((MB_HOST, MB_ENDPOINT_PORT), timeout=10.0) as c2:
        send_bytes(c2, b"SUBMIT_TOKENS")
        send_bytes(c2, session_id)
        send_int(c2, len(d_toks))
        for t in d_toks:
            send_bytes(c2, t)

        tag = recv_bytes(c2)
        if tag != b"DECISION":
            print(f"[sender] MB unexpected reply: {tag}")
            tls_conn.shutdown()
            return 2
        decision = recv_bytes(c2)
        m = recv_int(c2)
        for _ in range(m):
            rule_idx = recv_int(c2)
            pos = recv_int(c2)
            matches.append((rule_idx, pos))

    print(f"[sender] session={session_id.hex()} decision={decision.decode()} matches={matches}")

    if decision == b"DROP":
        tls_conn.shutdown()
        return 0

    # ALLOW: send HTTPS request
    req = build_http_post(host=TLS_SERVER_NAME, path="/submit", body=body, content_type="text/plain")
    tls_conn.sendall(req)

    # very small response read
    resp = b""
    try:
        while True:
            chunk = tls_conn.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 100000:
                break
    except Exception:
        pass

    print("[sender] response:")
    print(resp.decode("utf-8", "replace"))

    tls_conn.shutdown()
    return 0


def interactive_loop() -> int:
    print("PrivBox Sender Interactive Demo")
    print("Type a payload to send (or 'quit'/'exit' to stop).")
    while True:
        try:
            s = input("Enter payload> ").strip()
        except EOFError:
            return 0
        if s.lower() in ("quit", "exit"):
            return 0
        if not s:
            continue
        rc = run_once(s)
        if rc != 0:
            print(f"[sender] error (rc={rc})")


def main() -> None:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

    p = argparse.ArgumentParser()
    p.add_argument("--once", action="store_true", help="Send one payload then exit")
    p.add_argument("--payload", type=str, default="", help="Payload for --once mode")
    args = p.parse_args()

    if args.once:
        if not args.payload:
            raise SystemExit("--payload required with --once")
        raise SystemExit(run_once(args.payload))

    raise SystemExit(interactive_loop())


if __name__ == "__main__":
    main()
