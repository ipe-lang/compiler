#!/usr/bin/env python3
"""Tests for `ws_echo_server`: the echo it serves and every frame it refuses."""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ws_echo_server as ws  # noqa: E402

_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
_UPGRADE = (
    "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:8033\r\nUpgrade: websocket\r\n"
    "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Key: " + _KEY + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
)
_MASK = b"\x01\x02\x03\x04"


def _client_frame(opcode: int, payload: bytes, masked: bool = True, fin: bool = True, rsv: int = 0) -> bytes:
    b0 = (0x80 if fin else 0) | rsv | opcode
    n = len(payload)
    mbit = 0x80 if masked else 0
    if n < 126:
        head = struct.pack("!BB", b0, mbit | n)
    elif n < 1 << 16:
        head = struct.pack("!BBH", b0, mbit | 126, n)
    else:
        head = struct.pack("!BBQ", b0, mbit | 127, n)
    if not masked:
        return head + payload
    return head + _MASK + bytes(c ^ _MASK[i % 4] for i, c in enumerate(payload))


class _Conn:
    """A client socket wired to `serve_connection` on a thread."""

    def __init__(self) -> None:
        self.client, server = socket.socketpair()
        self.client.settimeout(5.0)
        self.error: list[BaseException] = []

        def run() -> None:
            try:
                ws.serve_connection(server)
            except (ws.Refused, OSError) as e:
                self.error.append(e)
            finally:
                server.close()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def read_all(self) -> bytes:
        buf = bytearray()
        while True:
            try:
                chunk = self.client.recv(65536)
            except ConnectionResetError:
                # The server closed with the refused bytes still unread.
                return bytes(buf)
            if not chunk:
                return bytes(buf)
            buf += chunk

    def handshake(self) -> None:
        self.client.sendall(_UPGRADE.encode("ascii"))
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = self.client.recv(4096)
            assert chunk, "server closed during handshake"
            buf += chunk
        head = bytes(buf).split(b"\r\n\r\n", 1)[0].decode("ascii")
        assert head.startswith("HTTP/1.1 101 "), head
        assert "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in head, head

    def finish(self) -> tuple[bytes, list[BaseException]]:
        rest = self.read_all()
        self.thread.join(5.0)
        self.client.close()
        return rest, self.error


class TestHandshake(unittest.TestCase):
    def test_accept_key_matches_rfc6455_example(self) -> None:
        self.assertEqual(ws.accept_key(_KEY), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_bad_upgrades_refused(self) -> None:
        for name, request, needle in (
            ("wrong path", _UPGRADE.replace("GET /ws ", "GET /other "), "is not /ws"),
            ("post", _UPGRADE.replace("GET ", "POST "), "not an HTTP/1.1 GET"),
            ("http 1.0", _UPGRADE.replace("HTTP/1.1\r\n", "HTTP/1.0\r\n", 1), "not an HTTP/1.1 GET"),
            ("no upgrade", _UPGRADE.replace("Upgrade: websocket\r\n", ""), "Upgrade: websocket"),
            ("no connection", _UPGRADE.replace("keep-alive, Upgrade", "keep-alive"), "Connection: Upgrade"),
            ("version 8", _UPGRADE.replace("Version: 13", "Version: 8"), "version 13"),
            ("short key", _UPGRADE.replace(_KEY, "AAAA"), "16 bytes"),
            ("bad key", _UPGRADE.replace(_KEY, "!!!!"), "not base64"),
            ("no colon", _UPGRADE.replace("Host: 127.0.0.1:8033", "Hostonly"), "no `:`"),
        ):
            with self.subTest(name):
                with self.assertRaises(ws.Refused) as ctx:
                    ws.parse_upgrade(request.split("\r\n\r\n", 1)[0].encode("ascii"))
                self.assertIn(needle, str(ctx.exception))

    def test_wrong_path_gets_400_and_close(self) -> None:
        conn = _Conn()
        conn.client.sendall(_UPGRADE.replace("GET /ws ", "GET /x ").encode("ascii"))
        rest, _ = conn.finish()
        self.assertTrue(rest.startswith(b"HTTP/1.1 400 "), rest)

    def test_oversized_upgrade_refused(self) -> None:
        conn = _Conn()
        head = b"GET /ws HTTP/1.1\r\nX: "
        conn.client.sendall(head + b"a" * (ws.MAX_REQUEST - len(head)))
        rest, _ = conn.finish()
        self.assertTrue(rest.startswith(b"HTTP/1.1 400 "), rest)


class TestFrames(unittest.TestCase):
    def test_echo_ping_and_close(self) -> None:
        conn = _Conn()
        conn.handshake()
        conn.client.sendall(_client_frame(0x1, b"hello-from-wasm-bindgen-test"))
        conn.client.sendall(_client_frame(0x9, b"p"))
        conn.client.sendall(_client_frame(0x8, b"\x03\xe8bye"))
        rest, error = conn.finish()
        self.assertEqual(
            rest,
            ws.frame(0x1, b"echo: hello-from-wasm-bindgen-test") + ws.frame(0xA, b"p") + ws.frame(0x8, b"\x03\xe8"),
        )
        self.assertEqual(error, [])

    def test_bad_frames_refused(self) -> None:
        big = ws.MAX_PAYLOAD + 1
        for name, raw, needle in (
            ("unmasked", _client_frame(0x1, b"x", masked=False), "must be masked"),
            ("fragment", _client_frame(0x1, b"x", fin=False), "fragmented"),
            ("reserved bit", _client_frame(0x1, b"x", rsv=0x40), "reserved bit"),
            ("binary", _client_frame(0x2, b"x"), "opcode 0x2"),
            ("bad utf-8", _client_frame(0x1, b"\xff"), "not UTF-8"),
            ("oversized", struct.pack("!BBQ", 0x81, 0xFF, big), f"payload of {big} bytes"),
            ("long control", _client_frame(0x9, b"x" * 126), "control frame exceeds"),
        ):
            with self.subTest(name):
                conn = _Conn()
                conn.handshake()
                conn.client.sendall(raw)
                rest, error = conn.finish()
                self.assertEqual(rest, b"")
                self.assertEqual(len(error), 1, error)
                self.assertIn(needle, str(error[0]))


class TestServer(unittest.TestCase):
    def test_loopback_echo_over_tcp(self) -> None:
        with ws.EchoServer(("127.0.0.1", 0)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with socket.create_connection(server.server_address, timeout=5.0) as client:
                    client.sendall(_UPGRADE.encode("ascii"))
                    buf = bytearray()
                    while b"\r\n\r\n" not in buf:
                        chunk = client.recv(4096)
                        self.assertTrue(chunk)
                        buf += chunk
                    self.assertTrue(buf.startswith(b"HTTP/1.1 101 "), buf)
                    client.sendall(_client_frame(0x1, b"hi"))
                    want = ws.frame(0x1, b"echo: hi")
                    got = bytearray()
                    while len(got) < len(want):
                        chunk = client.recv(4096)
                        self.assertTrue(chunk)
                        got += chunk
                    self.assertEqual(bytes(got), want)
            finally:
                server.shutdown()
                thread.join(5.0)

    def test_main_takes_no_arguments(self) -> None:
        self.assertEqual(ws.main(["--port", "1"]), 2)


if __name__ == "__main__":
    unittest.main()
