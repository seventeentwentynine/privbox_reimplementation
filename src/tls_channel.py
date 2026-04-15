from __future__ import annotations

import select
import socket
from dataclasses import dataclass
from typing import Tuple

from OpenSSL import SSL
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from config import CA_CERT_PATH


def _cert_has_dns_name(cert: x509.Certificate, expected_dns: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns = san.get_values_for_type(x509.DNSName)
        return expected_dns in dns
    except Exception:
        return False


def _wait_for_io(sock: socket.socket, want_read: bool, timeout: float = 10.0) -> None:
    if want_read:
        r, _, _ = select.select([sock], [], [], timeout)
        if not r:
            raise TimeoutError("Timed out waiting for TLS socket to become readable")
    else:
        _, w, _ = select.select([], [sock], [], timeout)
        if not w:
            raise TimeoutError("Timed out waiting for TLS socket to become writable")


def _drive_handshake(conn: SSL.Connection, sock: socket.socket, timeout: float = 10.0) -> None:
    while True:
        try:
            conn.do_handshake()
            return
        except SSL.WantReadError:
            _wait_for_io(sock, want_read=True, timeout=timeout)
        except SSL.WantWriteError:
            _wait_for_io(sock, want_read=False, timeout=timeout)


@dataclass
class TLSClient:
    server_name: str
    ca_cert_path: str = CA_CERT_PATH

    def connect(self, host: str, port: int, export_label: bytes, export_len: int) -> Tuple["TLSConnection", bytes]:
        tcp = socket.create_connection((host, port), timeout=10.0)
        tcp.setblocking(False)

        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_verify(SSL.VERIFY_PEER, callback=lambda *args: True)
        ctx.load_verify_locations(self.ca_cert_path)

        conn = SSL.Connection(ctx, tcp)
        conn.set_tlsext_host_name(self.server_name.encode("ascii"))
        conn.set_connect_state()

        _drive_handshake(conn, tcp, timeout=10.0)

        peer = conn.get_peer_certificate()
        if peer is None:
            raise RuntimeError("no peer certificate")

        peer_cert = peer.to_cryptography()
        if not _cert_has_dns_name(peer_cert, self.server_name):
            raise RuntimeError(f"peer cert missing SAN DNS={self.server_name}")

        ekm = conn.export_keying_material(export_label, export_len, context=None)
        return TLSConnection(conn=conn, tcp=tcp), ekm


@dataclass
class TLSServer:
    cert_path: str
    key_path: str

    def wrap_accepted(self, tcp: socket.socket, export_label: bytes, export_len: int) -> Tuple["TLSConnection", bytes]:
        tcp.setblocking(False)

        ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
        ctx.use_certificate_file(self.cert_path)
        ctx.use_privatekey_file(self.key_path)
        ctx.check_privatekey()

        conn = SSL.Connection(ctx, tcp)
        conn.set_accept_state()

        _drive_handshake(conn, tcp, timeout=10.0)

        ekm = conn.export_keying_material(export_label, export_len, context=None)
        return TLSConnection(conn=conn, tcp=tcp), ekm


@dataclass
class TLSConnection:
    conn: SSL.Connection
    tcp: socket.socket

    def sendall(self, data: bytes) -> None:
        view = memoryview(data)
        total = 0
        while total < len(data):
            try:
                sent = self.conn.send(view[total:])
                total += sent
            except SSL.WantReadError:
                _wait_for_io(self.tcp, want_read=True)
            except SSL.WantWriteError:
                _wait_for_io(self.tcp, want_read=False)

    def recv(self, n: int) -> bytes:
        while True:
            try:
                return self.conn.recv(n)
            except SSL.WantReadError:
                _wait_for_io(self.tcp, want_read=True)
            except SSL.WantWriteError:
                _wait_for_io(self.tcp, want_read=False)

    def shutdown(self) -> None:
        try:
            while True:
                try:
                    self.conn.shutdown()
                    break
                except SSL.WantReadError:
                    _wait_for_io(self.tcp, want_read=True)
                except SSL.WantWriteError:
                    _wait_for_io(self.tcp, want_read=False)
        finally:
            try:
                self.conn.close()
            finally:
                self.tcp.close()