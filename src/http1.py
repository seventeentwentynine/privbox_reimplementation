from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass(frozen=True)
class HTTPRequest:
    method: str
    path: str
    headers: Dict[str, str]
    body: bytes


def build_http_post(host: str, path: str, body: bytes, content_type: str = "text/plain") -> bytes:
    headers = {
        "Host": host,
        "User-Agent": "privbox-demo-sender/1.0",
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    lines = [f"POST {path} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
    return raw


def parse_http_request(raw_headers: bytes, body: bytes) -> HTTPRequest:
    text = raw_headers.decode("iso-8859-1")
    parts = text.split("\r\n")
    req_line = parts[0]
    method, path, _ver = req_line.split(" ", 2)
    headers: Dict[str, str] = {}
    for line in parts[1:]:
        if not line.strip():
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return HTTPRequest(method=method, path=path, headers=headers, body=body)
