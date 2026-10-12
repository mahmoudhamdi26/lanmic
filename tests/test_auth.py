"""Hub-mode hello authentication and pairing proxy."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

import lanmic


class _AuthHandler(BaseHTTPRequestHandler):
    accepted_token = "good-token"
    accepted_pin = "123456"

    def log_message(self, format, *args):  # noqa: A003
        return

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _write(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        payload = self._read_json()
        if self.path.endswith("/authorize"):
            if payload.get("token") == self.accepted_token:
                self._write(200, {"ok": True, "device_id": "dev-1", "device_name": "Pixel"})
            else:
                self._write(401, {"ok": False, "error": "unauthorized"})
            return
        if self.path.endswith("/pair"):
            if payload.get("pin") == self.accepted_pin:
                self._write(200, {"token": "issued-token", "device_id": "dev-1", "device_name": payload.get("device_name")})
            else:
                self._write(401, {"ok": False, "error": "bad pin"})
            return
        self._write(404, {"error": "missing"})


@pytest.fixture()
def auth_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    try:
        yield f"http://{host}:{port}/api/phone-mic/internal"
    finally:
        server.shutdown()
        server.server_close()


def test_parse_hello_requires_object():
    hello = lanmic.parse_hello('{"type":"hello","token":"abc","rate":16000}')
    assert hello["token"] == "abc"
    assert hello["rate"] == 16000
    with pytest.raises(json.JSONDecodeError):
        lanmic.parse_hello("not-json")
    with pytest.raises(ValueError):
        lanmic.parse_hello("[1]")


def test_authorize_hello_accepts_valid_token(auth_url):
    ok, body = lanmic.authorize_hello(auth_url, {"token": "good-token", "device": "Pixel", "client": "samox_android"})
    assert ok is True
    assert body["device_id"] == "dev-1"
    assert body["device_name"] == "Pixel"


def test_authorize_hello_rejects_missing_and_bad_token(auth_url):
    ok, body = lanmic.authorize_hello(auth_url, {"type": "hello"})
    assert ok is False
    assert "token" in str(body.get("error"))
    ok, body = lanmic.authorize_hello(auth_url, {"token": "wrong"})
    assert ok is False
    assert body.get("error") == "unauthorized"


def test_proxy_pair_issues_token(auth_url):
    status, body = lanmic.proxy_pair(auth_url, "123456", "Pixel 8")
    assert status == 200
    assert body["token"] == "issued-token"
    assert body["device_name"] == "Pixel 8"
    status, body = lanmic.proxy_pair(auth_url, "000000", "Pixel 8")
    assert status == 401


def test_info_marks_hub_kind_and_public_tls_port(tmp_path):
    server = lanmic.LanMicServer(
        "0.0.0.0",
        8766,
        8767,
        False,
        http_host="127.0.0.1",
        auth_url="http://127.0.0.1:8085/api/phone-mic/internal",
        data_dir=tmp_path,
        name="Kitchen",
        hub_uuid="11111111-1111-1111-1111-111111111111",
    )
    info = server.info()
    assert info["kind"] == "samox_hub"
    assert info["name"] == "Kitchen"
    assert info["hub_uuid"] == "11111111-1111-1111-1111-111111111111"
    assert info["ws_port"] == 8766
    assert info["https_port"] == 8766
    assert info["caps"] == ["mic", "speaker"]
    assert info["speaker_connected"] is False
    assert server.hub_mode() is True
