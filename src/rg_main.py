from __future__ import annotations

import socket
from pathlib import Path

from config import MB_HOST, MB_RULE_PREP_PORT, LOG_DIR
from framing import send_element, recv_element, send_bytes, recv_bytes, send_int, recv_int
from key_management import load_private_key, load_public_key
from protocols import RulePreparationRG, RGOutboundFig2Step5
from ruleset import load_ruleset_text, extract_rule_tokens


def main() -> None:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

    sk_rg = load_private_key("rg")
    _pk_rg = load_public_key("rg")  # not used by RG directly

    rules = extract_rule_tokens(load_ruleset_text())
    if not rules:
        raise RuntimeError("no rule tokens extracted")

    rg = RulePreparationRG(rules=rules, sk_sig_rg=sk_rg)

    with socket.create_connection((MB_HOST, MB_RULE_PREP_PORT), timeout=10.0) as sock:
        # Step 1: send (S_A, L)
        S_A, L = rg.step1_commitments()
        send_element(sock, S_A)
        send_element(sock, L)

        # Step 2: recv (S_B, S)
        S_B = recv_element(sock)
        S = recv_element(sock)

        # Step 3: send V_list
        V_list = rg.step3_compute_V(S_B, S)
        send_int(sock, len(V_list))
        for V_i in V_list:
            send_element(sock, V_i)

        # Step 4: recv (Y, R_tilde, S_i_list)
        Y = recv_bytes(sock)
        R_tilde = recv_element(sock)
        n = recv_int(sock)
        S_i_list = [recv_element(sock) for _ in range(n)]

        # Step 5: send msg
        msg: RGOutboundFig2Step5 = rg.step5_compute_and_sign(Y, R_tilde, S_i_list)
        send_element(sock, msg.R_hat)
        send_bytes(sock, msg.sig_rg_R)
        send_int(sock, len(msg.items))
        for (R_i, tilde_R_i, sig_tilde, hat_R_i, sig_hat) in msg.items:
            send_element(sock, R_i)
            send_element(sock, tilde_R_i)
            send_bytes(sock, sig_tilde)
            send_element(sock, hat_R_i)
            send_bytes(sock, sig_hat)

        ack = recv_bytes(sock).decode("utf-8", "replace")
        print(f"[rg] MB replied: {ack}")


if __name__ == "__main__":
    main()
