from __future__ import annotations

import socket
import struct
from typing import Any

from crypto import serialize_element, deserialize_element


def send_bytes(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_bytes(sock: socket.socket) -> bytes:
    header = _recv_exact(sock, 4)
    if not header:
        return b""
    (length,) = struct.unpack("!I", header)
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def send_int(sock: socket.socket, n: int) -> None:
    send_bytes(sock, struct.pack("!Q", n))


def recv_int(sock: socket.socket) -> int:
    b = recv_bytes(sock)
    if len(b) != 8:
        raise ValueError("expected uint64")
    return struct.unpack("!Q", b)[0]


def send_str(sock: socket.socket, s: str) -> None:
    send_bytes(sock, s.encode("utf-8"))


def recv_str(sock: socket.socket) -> str:
    return recv_bytes(sock).decode("utf-8")


def send_element(sock: socket.socket, element: Any) -> None:
    send_bytes(sock, serialize_element(element))


def recv_element(sock: socket.socket) -> Any:
    return deserialize_element(recv_bytes(sock))


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf
