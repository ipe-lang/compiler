#!/usr/bin/env python3
"""Loopback WebSocket echo server for the browser WebSocket bridge test.

Serves `ws://127.0.0.1:8033/ws` and answers every text frame with the same
text prefixed `echo: `. Stdlib only, loopback only, and bounded: at most
`MAX_CONNECTIONS` sockets at once, an upgrade request of at most
`MAX_REQUEST` bytes, a frame payload of at most `MAX_PAYLOAD` bytes, and
`TIMEOUT` seconds of silence per read. An unmasked client frame, a fragmented
message, a reserved bit, an unknown opcode, invalid UTF-8, a path other than
`/ws`, or a malformed upgrade closes the connection; nothing else is served.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import socketserver
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = 8033
PATH = "/ws"
MAX_CONNECTIONS = 8
MAX_REQUEST = 8 * 1024
MAX_PAYLOAD = 64 * 1024
TIMEOUT = 30.0
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_TEXT, _CLOSE, _PING, _PONG = 0x1, 0x8, 0x9, 0xA


class Refused(Exception):
    """The peer broke the protocol or a bound; the connection is dropped."""


def accept_key(key: str) -> str:
    """The `Sec-WebSocket-Accept` value for a client `Sec-WebSocket-Key`."""
    return base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")


def parse_upgrade(request: bytes) -> str:
    """The client key of a well-formed `GET /ws` upgrade, else `Refused`."""
    try:
        text = request.decode("ascii")
    except UnicodeDecodeError as e:
        raise Refused("the upgrade request is not ASCII") from e
    lines = text.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[0] != "GET" or parts[2] != "HTTP/1.1":
        raise Refused("not an HTTP/1.1 GET")
    if parts[1] != PATH:
        raise Refused(f"path {parts[1]!r} is not {PATH}")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep:
            raise Refused("a header line has no `:`")
        headers[name.strip().lower()] = value.strip()
    if headers.get("upgrade", "").lower() != "websocket":
        raise Refused("no `Upgrade: websocket`")
    if "upgrade" not in [t.strip().lower() for t in headers.get("connection", "").split(",")]:
        raise Refused("no `Connection: Upgrade`")
    if headers.get("sec-websocket-version") != "13":
        raise Refused("not WebSocket version 13")
    key = headers.get("sec-websocket-key", "")
    try:
        if len(base64.b64decode(key, validate=True)) != 16:
            raise Refused("the key is not 16 bytes")
    except ValueError as e:
        raise Refused("the key is not base64") from e
    return key


def _read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise Refused("the peer closed mid-frame")
        buf += chunk
    return bytes(buf)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    """One client frame as (opcode, unmasked payload), else `Refused`."""
    b0, b1 = _read_exact(sock, 2)
    if not b0 & 0x80:
        raise Refused("fragmented messages are not served")
    if b0 & 0x70:
        raise Refused("a reserved bit is set")
    if not b1 & 0x80:
        raise Refused("a client frame must be masked")
    opcode, length = b0 & 0x0F, b1 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", _read_exact(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", _read_exact(sock, 8))
    if opcode >= 0x8 and length > 125:
        raise Refused("a control frame exceeds 125 bytes")
    if length > MAX_PAYLOAD:
        raise Refused(f"a payload of {length} bytes exceeds {MAX_PAYLOAD}")
    mask = _read_exact(sock, 4)
    data = _read_exact(sock, length)
    return opcode, bytes(c ^ mask[i % 4] for i, c in enumerate(data))


def frame(opcode: int, payload: bytes) -> bytes:
    """One unmasked server frame."""
    n = len(payload)
    if n < 126:
        head = struct.pack("!BB", 0x80 | opcode, n)
    elif n < 1 << 16:
        head = struct.pack("!BBH", 0x80 | opcode, 126, n)
    else:
        head = struct.pack("!BBQ", 0x80 | opcode, 127, n)
    return head + payload


def _read_request(sock: socket.socket) -> bytes:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) >= MAX_REQUEST:
            raise Refused(f"the upgrade request exceeds {MAX_REQUEST} bytes")
        chunk = sock.recv(MAX_REQUEST - len(buf))
        if not chunk:
            raise Refused("the peer closed before the upgrade finished")
        buf += chunk
    end = buf.index(b"\r\n\r\n")
    if end + 4 != len(buf):
        raise Refused("data followed the upgrade request before the handshake")
    return bytes(buf[:end])


def serve_connection(sock: socket.socket) -> None:
    """Handshake, then echo text frames until the peer closes or errs."""
    sock.settimeout(TIMEOUT)
    try:
        key = parse_upgrade(_read_request(sock))
    except Refused:
        sock.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    sock.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept_key(key).encode("ascii") + b"\r\n\r\n"
    )
    while True:
        opcode, payload = read_frame(sock)
        if opcode == _TEXT:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as e:
                raise Refused("a text frame is not UTF-8") from e
            sock.sendall(frame(_TEXT, ("echo: " + text).encode("utf-8")))
        elif opcode == _PING:
            sock.sendall(frame(_PONG, payload))
        elif opcode == _PONG:
            continue
        elif opcode == _CLOSE:
            sock.sendall(frame(_CLOSE, payload[:2]))
            return
        else:
            raise Refused(f"opcode {opcode:#x} is not served")


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        assert isinstance(server, EchoServer)
        if not server.slots.acquire(blocking=False):
            return
        try:
            serve_connection(self.request)
        except (Refused, OSError):
            pass
        finally:
            server.slots.release()


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int]) -> None:
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, _Handler)


def main(argv: list[str]) -> int:
    if argv:
        sys.stderr.write("usage: ws_echo_server.py\n")
        return 2
    with EchoServer((HOST, PORT)) as server:
        sys.stderr.write(f"ws_echo_server: serving ws://{HOST}:{PORT}{PATH}\n")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
