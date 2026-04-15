#!/usr/bin/env python3
from __future__ import annotations

import argparse
import socket
import sys
import time


def wait_for(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()

    ok = wait_for(args.host, args.port, args.timeout)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
