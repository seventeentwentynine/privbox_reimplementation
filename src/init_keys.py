from __future__ import annotations

from key_management import ensure_keypair


def main() -> None:
    ensure_keypair("rg")
    ensure_keypair("mb")
    print("[init_keys] signature keys ready")


if __name__ == "__main__":
    main()
