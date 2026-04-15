from __future__ import annotations

import socket
from pathlib import Path

from config import (
    LOG_DIR,
    MB_HOST,
    MB_ENDPOINT_PORT,
    LISTEN_HOST,
    LISTEN_PORT,
    RECEIVER_CERT_PATH,
    RECEIVER_KEY_PATH,
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
)
from http1 import parse_http_request, HTTPRequest
from kdf import derive_endpoint_secrets, session_id_from_exporter
from key_management import load_public_key
from protocols import PreprocessingEndpoint, TokenEncryptor
from tokenization import window_tokenize
from tls_channel import TLSServer


def _recv_until(conn, marker: bytes, max_bytes: int = 65536) -> bytes:
    buf = b""
    while marker not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            break
    return buf


def _read_http_over_tls(tls_conn) -> HTTPRequest:
    # Read headers
    raw = _recv_until(tls_conn, b"\r\n\r\n", max_bytes=200000)
    if b"\r\n\r\n" not in raw:
        raise RuntimeError("incomplete HTTP headers")
    head, rest = raw.split(b"\r\n\r\n", 1)
    # Parse content-length
    headers_txt = head.decode("iso-8859-1")
    lines = headers_txt.split("\r\n")
    cl = 0
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            if k.strip().lower() == "content-length":
                cl = int(v.strip())
    body = rest
    while len(body) < cl:
        chunk = tls_conn.recv(min(4096, cl - len(body)))
        if not chunk:
            break
        body += chunk
    return parse_http_request(head + b"\r\n", body[:cl])


def main() -> None:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
    accepted_log = Path(LOG_DIR) / "receiver_accepted.log"
    invalid_log = Path(LOG_DIR) / "receiver_invalid.log"

    pk_rg = load_public_key("rg")
    pk_mb = load_public_key("mb")

    srv = TLSServer(cert_path=RECEIVER_CERT_PATH, key_path=RECEIVER_KEY_PATH)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LISTEN_HOST, LISTEN_PORT))
        sock.listen(50)
        print(f"[receiver] listening on {LISTEN_HOST}:{LISTEN_PORT}")

        while True:
            tcp, addr = sock.accept()
            try:
                tls_conn, ekm = srv.wrap_accepted(tcp, export_label=TLS_EXPORT_LABEL, export_len=TLS_EXPORT_LEN)
                session_id = session_id_from_exporter(ekm)
                secrets = derive_endpoint_secrets(ekm)

                # Preprocessing as receiver
                ep = PreprocessingEndpoint(secrets.k_s1, secrets.k_s2, pk_sig_rg=pk_rg, pk_sig_mb=pk_mb)

                with socket.create_connection((MB_HOST, MB_ENDPOINT_PORT), timeout=10.0) as c:
                    send_bytes(c, b"PREP_HELLO")
                    send_bytes(c, session_id)
                    send_bytes(c, b"R")
                    # receiver provides no flow id
                    from framing import send_str
                    send_str(c, "")
                    send_int(c, 0)

                    tag = recv_bytes(c)
                    if tag != b"PREP_SETUP":
                        raise RuntimeError(f"MB refused preprocessing: {tag}")

                    n = recv_int(c)

                    # read SetupState-like values
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
                        raise RuntimeError(f"preprocessing failed: {done}")

                # Receive HTTP request
                req = _read_http_over_tls(tls_conn)
                payload = req.body

                # Fetch token stream from MB
                tokens = None
                for _ in range(30):
                    with socket.create_connection((MB_HOST, MB_ENDPOINT_PORT), timeout=10.0) as c3:
                        send_bytes(c3, b"GET_TOKENS")
                        send_bytes(c3, session_id)
                        tag = recv_bytes(c3)
                        if tag == b"TOKEN_STREAM":
                            m = recv_int(c3)
                            tokens = [recv_bytes(c3) for _ in range(m)]
                            break
                    import time
                    time.sleep(0.1)

                if tokens is None:
                    raise RuntimeError("token stream not available for validation")

                if ep.R is None:
                    raise RuntimeError("missing R after preprocessing")
                enc = TokenEncryptor(R=ep.R, k_s1=secrets.k_s1, k_s2=secrets.k_s2, S_salt=secrets.S_salt, K_s=None)
                expected = [enc.encrypt_token(t) for t in window_tokenize(payload)]

                valid = (len(expected) == len(tokens)) and all(a == b for a, b in zip(expected, tokens))
                if valid:
                    accepted_log.write_text(
                        accepted_log.read_text(encoding="utf-8") + f"session={session_id.hex()} path={req.path} payload={payload.decode('utf-8','replace')}\n"
                        if accepted_log.exists()
                        else f"session={session_id.hex()} path={req.path} payload={payload.decode('utf-8','replace')}\n",
                        encoding="utf-8",
                    )
                    resp_body = b"ACCEPT\n"
                    status = b"HTTP/1.1 200 OK\r\n"
                else:
                    invalid_log.write_text(
                        invalid_log.read_text(encoding="utf-8") + f"session={session_id.hex()} INVALID payload={payload.decode('utf-8','replace')}\n"
                        if invalid_log.exists()
                        else f"session={session_id.hex()} INVALID payload={payload.decode('utf-8','replace')}\n",
                        encoding="utf-8",
                    )
                    resp_body = b"INVALID\n"
                    status = b"HTTP/1.1 400 Bad Request\r\n"

                resp = (
                    status
                    + b"Content-Type: text/plain\r\n"
                    + f"Content-Length: {len(resp_body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + resp_body
                )
                tls_conn.sendall(resp)
                tls_conn.shutdown()

            except Exception as e:
                try:
                    tcp.close()
                except Exception:
                    pass
                # best-effort; receiver keeps serving
                print(f"[receiver] error: {e}")


if __name__ == "__main__":
    # docker-compose injects LISTEN_HOST/LISTEN_PORT env via config.py;
    # for local runs, default in docker-compose is 0.0.0.0:8443
    main()
