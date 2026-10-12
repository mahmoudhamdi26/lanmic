#!/usr/bin/env python3
"""LanMic: stream a phone microphone into a PipeWire virtual mic over Wi-Fi."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus
from pathlib import Path
from typing import Any

from websockets.asyncio.server import ServerConnection, serve
from websockets.http11 import Request, Response

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DEFAULT_DATA = Path.home() / ".local" / "share" / "lanmic"
SOURCE_NAME = "LanMic"
BRIDGE_NAME = "LanMicBridge"
SOURCE_DESCRIPTION = "Phone microphone"
SINK_NAME = "PhoneSpeaker"
SINK_DESCRIPTION = "Phone speaker"
DEFAULT_PORT = 8766
DISCOVER_PORT = 8768
DISCOVER_QUERY = (b"LANMIC?", b"LANMIC")
HUB_CAPS = ["mic", "speaker"]


def _is_lan_ip(ip: str) -> bool:
    return bool(ip) and not ip.startswith("127.") and not ip.startswith("169.254.")


def lan_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 80))
        ip = probe.getsockname()[0]
        if _is_lan_ip(ip):
            return ip
    except OSError:
        pass
    finally:
        probe.close()
    try:
        listing = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            text=True,
        )
        for line in listing.splitlines():
            parts = line.split()
            if "inet" in parts:
                ip = parts[parts.index("inet") + 1].split("/")[0]
                if _is_lan_ip(ip):
                    return ip
    except (OSError, subprocess.CalledProcessError):
        pass
    return "127.0.0.1"


def wait_lan_ip(timeout: float = 20.0) -> str:
    deadline = time.monotonic() + timeout
    ip = lan_ip()
    while not _is_lan_ip(ip) and time.monotonic() < deadline:
        time.sleep(0.4)
        ip = lan_ip()
    return ip


def cert_paths(data_dir: Path) -> tuple[Path, Path, Path]:
    return data_dir / "cert.pem", data_dir / "key.pem", data_dir / "ip.txt"


def cert_fingerprint(cert_path: Path) -> str:
    """Return the SPKI SHA-256 fingerprint as standard base64."""
    pub = subprocess.check_output(
        ["openssl", "x509", "-in", str(cert_path), "-noout", "-pubkey"],
    )
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-outform", "der"],
        input=pub,
    )
    digest = subprocess.check_output(["openssl", "dgst", "-sha256", "-binary"], input=der)
    return base64.b64encode(digest).decode("ascii")


def ensure_certs(ip: str, data_dir: Path, stable: bool = False) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    cert, key, cert_ip = cert_paths(data_dir)
    if cert.exists() and key.exists():
        if stable:
            return
        if cert_ip.exists() and cert_ip.read_text(encoding="utf-8").strip() == ip:
            return
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "825",
            "-nodes", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=LanMic",
            "-addext", f"subjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    cert_ip.write_text(ip + "\n", encoding="utf-8")
    print(f"Created TLS certificate for {ip}", flush=True)


def http_json(
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 3.0,
) -> tuple[int, dict[str, Any]]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body) if body else {}
            if not isinstance(parsed, dict):
                parsed = {"value": parsed}
            return int(response.status), parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"detail": raw}
        if not isinstance(parsed, dict):
            parsed = {"detail": raw}
        return int(exc.code), parsed
    except Exception as exc:
        return 0, {"error": str(exc)}


def authorize_hello(auth_url: str, hello: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    token = str(hello.get("token") or "").strip()
    if not token:
        return False, {"error": "missing token"}
    status, body = http_json(
        "POST",
        f"{auth_url.rstrip('/')}/authorize",
        {
            "token": token,
            "device": hello.get("device") or hello.get("device_name") or "",
            "client": hello.get("client") or "",
            "caps": hello.get("caps") or HUB_CAPS,
        },
    )
    if status == 200 and body.get("ok") is True:
        return True, body
    return False, body


def proxy_pair(auth_url: str, pin: str, device_name: str) -> tuple[int, dict[str, Any]]:
    return http_json(
        "POST",
        f"{auth_url.rstrip('/')}/pair",
        {"pin": pin, "device_name": device_name},
    )


def post_event(auth_url: str, event: dict[str, Any]) -> None:
    http_json("POST", f"{auth_url.rstrip('/')}/event", event, timeout=2.0)


def parse_hello(message: str) -> dict[str, Any]:
    hello = json.loads(message)
    if not isinstance(hello, dict):
        raise ValueError("hello must be an object")
    return hello


class DiscoverProtocol(asyncio.DatagramProtocol):
    """Reply to LAN broadcasts so the phone can list every running PC."""

    def __init__(self, payload_fn) -> None:
        self.payload_fn = payload_fn
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        if data.strip().upper() not in DISCOVER_QUERY or self.transport is None:
            return
        try:
            self.transport.sendto(self.payload_fn(), addr)
        except OSError:
            pass


def print_qr(url: str) -> None:
    qrencode = shutil.which("qrencode")
    if not qrencode:
        print(url, flush=True)
        return
    print(flush=True)
    subprocess.run([qrencode, "-t", "ANSIUTF8", url], check=False)
    print(flush=True)


def pactl_names(kind: str) -> set[str]:
    listing = subprocess.check_output(["pactl", "list", "short", kind], text=True)
    names = set()
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            names.add(parts[1])
    return names


def load_module(args: list[str]) -> str:
    return subprocess.check_output(["pactl", "load-module", *args], text=True).strip()


def pw_ports(kind: str) -> list[str]:
    flag = "-o" if kind == "output" else "-i"
    return [line.strip() for line in subprocess.check_output(["pw-link", flag], text=True).splitlines() if line.strip()]


def link_ports(src: str, dst: str) -> None:
    subprocess.run(["pw-link", src, dst], check=False, capture_output=True)


class PipeWireMic:
    def __init__(self) -> None:
        self.module_ids: list[str] = []
        self.player: asyncio.subprocess.Process | None = None
        self.bytes_in = 0
        self.peak = 0
        self.last_log = 0.0

    def create_source(self) -> None:
        names = pactl_names("sinks") | pactl_names("sources")
        description = SOURCE_DESCRIPTION.replace(" ", r"\ ")
        if BRIDGE_NAME not in names:
            self.module_ids.append(load_module([
                "module-null-sink",
                f"sink_name={BRIDGE_NAME}",
                (
                    f"sink_properties=device.description={BRIDGE_NAME} "
                    "device.class=filter node.virtual=true"
                ),
                "channel_map=mono",
            ]))
        if SOURCE_NAME not in pactl_names("sources"):
            self.module_ids.append(load_module([
                "module-null-sink",
                "media.class=Audio/Source/Virtual",
                f"sink_name={SOURCE_NAME}",
                f"sink_properties=device.description={description}",
                "channel_map=mono",
            ]))
        self._link_bridge()
        print(f"PipeWire source {SOURCE_NAME} ready", flush=True)

    def source_present(self) -> bool:
        return SOURCE_NAME in pactl_names("sources")

    def ensure_source(self) -> bool:
        if self.source_present() and BRIDGE_NAME in pactl_names("sinks"):
            return False
        print("LanMic PipeWire nodes missing; recreating", flush=True)
        self.module_ids.clear()
        self.create_source()
        return True

    def _link_bridge(self) -> None:
        for _ in range(25):
            outputs = [p for p in pw_ports("output") if p.startswith(f"{BRIDGE_NAME}:monitor")]
            inputs = [p for p in pw_ports("input") if p.startswith(f"{SOURCE_NAME}:input")]
            if outputs and inputs:
                for i, src in enumerate(outputs):
                    link_ports(src, inputs[min(i, len(inputs) - 1)])
                return
            time.sleep(0.05)
        print("Warning: could not link LanMicBridge to LanMic", flush=True)

    def _link_player(self) -> None:
        for _ in range(30):
            outputs = [
                p
                for p in pw_ports("output")
                if p.startswith("lanmic-player:output") or p.startswith("pw-cat:output")
            ]
            if outputs:
                inputs = [p for p in pw_ports("input") if p.startswith(f"{SOURCE_NAME}:input")]
                dest = inputs[0] if inputs else f"{SOURCE_NAME}:input_MONO"
                for src in outputs:
                    link_ports(src, dest)
                print(f"Routed phone audio directly into {SOURCE_NAME}", flush=True)
                return
            time.sleep(0.05)
        print("Warning: pw-cat ports not found", flush=True)

    def player_argv(self, rate: int) -> list[str]:
        return [
            "pw-cat",
            "-p",
            "--raw",
            "--rate", str(rate),
            "--channels", "1",
            "--channel-map", "MONO",
            "--format", "s16",
            "--latency", "5ms",
            "--target", "0",
            "--media-type", "Audio",
            "--media-category", "Playback",
            "--media-role", "Production",
            "-P", "node.name=lanmic-player",
            "-P", "node.dont-fallback=true",
            "-P", f"node.latency=256/{rate}",
            "-",
        ]

    async def start_player(self, rate: int) -> None:
        await self.stop_player()
        self.bytes_in = 0
        self.peak = 0
        self.last_log = time.monotonic()
        self.player = await asyncio.create_subprocess_exec(
            *self.player_argv(rate),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(0.15)
        await asyncio.to_thread(self._link_player)

    async def write(self, pcm: bytes) -> None:
        if not self.player or not self.player.stdin:
            raise RuntimeError("PipeWire player is not running")
        self.bytes_in += len(pcm)
        if len(pcm) >= 2:
            count = min(len(pcm) // 2, 480)
            samples = struct.unpack_from("<" + "h" * count, pcm)
            local_peak = max((abs(s) for s in samples), default=0)
            if local_peak > self.peak:
                self.peak = local_peak
        transport = getattr(self.player.stdin, "transport", None)
        queued = transport.get_write_buffer_size() if transport else 0
        if queued > 960:
            return
        self.player.stdin.write(pcm)
        now = time.monotonic()
        if now - self.last_log >= 2:
            print(
                f"Audio from phone: {self.bytes_in} bytes, peak={self.peak}",
                flush=True,
            )
            self.peak = 0
            self.last_log = now

    async def stop_player(self) -> None:
        proc = self.player
        self.player = None
        if not proc:
            return
        if proc.stdin:
            proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), timeout=1.5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    def destroy_source(self) -> None:
        for module_id in reversed(self.module_ids):
            subprocess.run(["pactl", "unload-module", module_id], check=False)
        self.module_ids.clear()


class PipeWireSpeaker:
    def __init__(self) -> None:
        self.module_ids: list[str] = []
        self.recorder: asyncio.subprocess.Process | None = None
        self.bytes_out = 0
        self.peak = 0

    def create_sink(self) -> None:
        names = pactl_names("sinks")
        description = SINK_DESCRIPTION.replace(" ", r"\ ")
        if SINK_NAME not in names:
            self.module_ids.append(load_module([
                "module-null-sink",
                f"sink_name={SINK_NAME}",
                (
                    f"sink_properties=device.description={description} "
                    "device.class=sound node.virtual=true"
                ),
                "channel_map=mono",
            ]))
        print(f"PipeWire sink {SINK_NAME} ready", flush=True)

    def sink_present(self) -> bool:
        return SINK_NAME in pactl_names("sinks")

    def ensure_sink(self) -> bool:
        if self.sink_present():
            return False
        print("PhoneSpeaker PipeWire node missing; recreating", flush=True)
        self.module_ids.clear()
        self.create_sink()
        return True

    def record_target(self) -> str | None:
        monitor = f"{SINK_NAME}.monitor"
        if monitor in pactl_names("sources"):
            return monitor
        return None

    def wait_monitor(self, timeout: float = 2.0) -> str | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            target = self.record_target()
            if target:
                return target
            time.sleep(0.05)
        return None

    def recorder_argv(self, rate: int) -> list[str]:
        return [
            "pw-cat",
            "-r",
            "--raw",
            "--rate", str(rate),
            "--channels", "1",
            "--channel-map", "MONO",
            "--format", "s16",
            "--latency", "20ms",
            "--target", "0",
            "--media-type", "Audio",
            "--media-category", "Capture",
            "--media-role", "Production",
            "-P", "node.name=lanmic-speaker",
            "-P", "node.dont-fallback=true",
            "-",
        ]

    def _link_recorder(self) -> None:
        for _ in range(30):
            outputs = [p for p in pw_ports("output") if p.startswith(f"{SINK_NAME}:monitor")]
            inputs = [
                p
                for p in pw_ports("input")
                if p.startswith("lanmic-speaker:input") or p.startswith("pw-cat:input")
            ]
            if outputs and inputs:
                for i, dst in enumerate(inputs):
                    link_ports(outputs[min(i, len(outputs) - 1)], dst)
                print(f"Pinned speaker capture to {SINK_NAME}.monitor", flush=True)
                return
            time.sleep(0.05)
        print("Warning: could not pin speaker capture to PhoneSpeaker.monitor", flush=True)

    async def start_recorder(self, rate: int) -> None:
        await self.stop_recorder()
        self.bytes_out = 0
        self.peak = 0
        await asyncio.to_thread(self.ensure_sink)
        if not await asyncio.to_thread(self.wait_monitor):
            print("PhoneSpeaker.monitor missing; refusing to record the default source", flush=True)
            return
        self.recorder = await asyncio.create_subprocess_exec(
            *self.recorder_argv(rate),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(0.1)
        if self.recorder.returncode is not None:
            err = b""
            if self.recorder.stderr:
                err = await self.recorder.stderr.read()
            print(
                f"pw-cat record failed: {err.decode('utf-8', errors='replace').strip()}",
                flush=True,
            )
            self.recorder = None
            return
        await asyncio.to_thread(self._link_recorder)
        print(f"Recording hub playback from {SINK_NAME}.monitor", flush=True)

    async def read_chunk(self, size: int = 1280) -> bytes:
        if not self.recorder or not self.recorder.stdout:
            return b""
        data = await self.recorder.stdout.read(size)
        if data:
            self.bytes_out += len(data)
            if len(data) >= 2:
                count = min(len(data) // 2, 480)
                samples = struct.unpack_from("<" + "h" * count, data)
                local_peak = max((abs(s) for s in samples), default=0)
                if local_peak > self.peak:
                    self.peak = local_peak
        return data

    async def stop_recorder(self) -> None:
        proc = self.recorder
        self.recorder = None
        if not proc:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=1.5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    def destroy_sink(self) -> None:
        for module_id in reversed(self.module_ids):
            subprocess.run(["pactl", "unload-module", module_id], check=False)
        self.module_ids.clear()


class LanMicServer:
    def __init__(
        self,
        host: str,
        port: int,
        http_port: int,
        set_default: bool,
        *,
        http_host: str = "0.0.0.0",
        auth_url: str = "",
        data_dir: Path | None = None,
        stable_cert: bool = False,
        name: str = "",
        hub_uuid: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.http_port = http_port
        self.http_host = http_host
        self.set_default = set_default
        self.auth_url = auth_url.rstrip("/")
        self.data_dir = data_dir or DEFAULT_DATA
        self.stable_cert = stable_cert
        self.display_name = name or socket.gethostname()
        self.hub_uuid = hub_uuid
        self.fingerprint = ""
        self.mic = PipeWireMic()
        self.speaker = PipeWireSpeaker()
        self.active: ServerConnection | None = None
        self.speaker_ws: ServerConnection | None = None
        self.active_device: dict[str, Any] = {}
        self.speaker_device: dict[str, Any] = {}
        self.static = {
            "/": (WEB / "index.html", "text/html; charset=utf-8"),
            "/index.html": (WEB / "index.html", "text/html; charset=utf-8"),
            "/manifest.json": (WEB / "manifest.json", "application/manifest+json"),
        }

    def hub_mode(self) -> bool:
        return bool(self.auth_url)

    def public_ws_port(self) -> int:
        if self.hub_mode() or self.http_host in {"127.0.0.1", "::1", "localhost"}:
            return self.port
        return self.http_port

    def info(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "service": "lanmic",
            "name": self.display_name,
            "ip": lan_ip(),
            "port": self.public_ws_port(),
            "ws_port": self.public_ws_port(),
            "https_port": self.port,
            "connected": self.active is not None,
            "speaker_connected": self.speaker_ws is not None,
            "caps": list(HUB_CAPS),
        }
        if self.fingerprint:
            payload["fingerprint"] = self.fingerprint
        if self.hub_mode():
            payload["kind"] = "samox_hub"
            if self.hub_uuid:
                payload["hub_uuid"] = self.hub_uuid
            if self.active_device:
                payload["device_id"] = self.active_device.get("device_id")
                payload["device_name"] = self.active_device.get("device_name")
            if self.speaker_device:
                payload["speaker_device_id"] = self.speaker_device.get("device_id")
                payload["speaker_device_name"] = self.speaker_device.get("device_name")
        return payload

    def discover_bytes(self) -> bytes:
        return json.dumps(self.info()).encode("utf-8")

    def _json_response(self, connection: ServerConnection, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> Response:
        response = connection.respond(status, json.dumps(payload))
        response.headers["Content-Type"] = "application/json"
        response.headers["Cache-Control"] = "no-store"
        return response

    def process_request(self, connection: ServerConnection, request: Request) -> Response | None:
        parsed = urllib.parse.urlparse(request.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        if path in ("/ws", "/ws/speaker"):
            return None
        if path == "/pair":
            if not self.auth_url:
                return self._json_response(
                    connection,
                    {"ok": False, "error": "pairing is only available in hub mode"},
                    HTTPStatus.NOT_FOUND,
                )
            pin = (query.get("pin") or [""])[0]
            device_name = (query.get("device_name") or query.get("name") or [""])[0]
            status, body = proxy_pair(self.auth_url, pin, device_name)
            http_status = HTTPStatus.OK if status == 200 else HTTPStatus.FORBIDDEN
            if status == 200:
                http_status = HTTPStatus.OK
            elif status == 401:
                http_status = HTTPStatus.UNAUTHORIZED
            elif status == 404:
                http_status = HTTPStatus.NOT_FOUND
            elif status == 0:
                http_status = HTTPStatus.BAD_GATEWAY
            else:
                http_status = HTTPStatus.FORBIDDEN
            return self._json_response(connection, body, http_status)
        if path in ("/info", "/status"):
            payload = self.info()
            if path == "/status":
                payload = {
                    **payload,
                    "source": SOURCE_NAME,
                    "source_description": SOURCE_DESCRIPTION,
                    "playing": self.mic.player is not None,
                    "bytes": self.mic.bytes_in,
                    "peak": self.mic.peak,
                    "sink": SINK_NAME,
                    "sink_description": SINK_DESCRIPTION,
                    "speaker_playing": self.speaker.recorder is not None,
                    "speaker_bytes": self.speaker.bytes_out,
                    "speaker_peak": self.speaker.peak,
                }
            return self._json_response(connection, payload)
        asset = self.static.get(path)
        if not asset:
            return connection.respond(HTTPStatus.NOT_FOUND, "Not found")
        path_obj, content_type = asset
        response = connection.respond(HTTPStatus.OK, path_obj.read_text(encoding="utf-8"))
        response.headers["Content-Type"] = content_type
        response.headers["Cache-Control"] = "no-store"
        return response

    def _ws_path(self, websocket: ServerConnection) -> str:
        request = getattr(websocket, "request", None)
        raw = getattr(request, "path", "") if request is not None else ""
        return urllib.parse.urlparse(str(raw or "")).path

    async def handler(self, websocket: ServerConnection) -> None:
        if self._ws_path(websocket) == "/ws/speaker":
            await self.speaker_handler(websocket)
            return
        await self.mic_handler(websocket)

    async def mic_handler(self, websocket: ServerConnection) -> None:
        if self.active is not None:
            await websocket.close(4000, "Another phone is already streaming")
            return
        self.active = websocket
        rate = 48000
        device: dict[str, Any] = {}
        try:
            first = await websocket.recv()
            if isinstance(first, bytes):
                if self.hub_mode():
                    await websocket.close(4001, "hello required")
                    return
                await self.mic.start_player(rate)
                await self.mic.write(first)
            else:
                hello = parse_hello(first)
                if hello.get("type") == "pair":
                    if not self.auth_url:
                        await websocket.close(4001, "pairing is only available in hub mode")
                        return
                    status, body = await asyncio.to_thread(
                        proxy_pair,
                        self.auth_url,
                        str(hello.get("pin") or ""),
                        str(hello.get("device_name") or hello.get("name") or ""),
                    )
                    await websocket.send(json.dumps({"type": "paired" if status == 200 else "error", **body}))
                    await websocket.close(1000 if status == 200 else 4001, "pair")
                    return
                if self.hub_mode():
                    ok, device = await asyncio.to_thread(authorize_hello, self.auth_url, hello)
                    if not ok:
                        await websocket.close(4001, str(device.get("error") or device.get("detail") or "unauthorized"))
                        return
                    self.active_device = {
                        "device_id": device.get("device_id"),
                        "device_name": device.get("device_name") or hello.get("device") or "",
                        "client": hello.get("client") or "",
                    }
                rate = int(hello.get("rate") or 48000)
                await self.mic.start_player(rate)
                await websocket.send(json.dumps({"type": "ready", "caps": list(HUB_CAPS)}))
            print(f"Phone connected ({rate} Hz)", flush=True)
            if self.auth_url:
                await asyncio.to_thread(
                    post_event,
                    self.auth_url,
                    {
                        "type": "connected",
                        "device_id": self.active_device.get("device_id"),
                        "device_name": self.active_device.get("device_name"),
                        "client": self.active_device.get("client"),
                        "rate": rate,
                    },
                )
            async for message in websocket:
                if isinstance(message, bytes):
                    await self.mic.write(message)
        except Exception as exc:
            print(f"Stream ended: {exc}", flush=True)
        finally:
            if self.active is websocket:
                self.active = None
            device = dict(self.active_device)
            self.active_device = {}
            await self.mic.stop_player()
            if self.auth_url and device:
                await asyncio.to_thread(
                    post_event,
                    self.auth_url,
                    {
                        "type": "disconnected",
                        "device_id": device.get("device_id"),
                        "device_name": device.get("device_name"),
                        "client": device.get("client"),
                    },
                )
            print("Phone disconnected", flush=True)

    async def speaker_handler(self, websocket: ServerConnection) -> None:
        if self.speaker_ws is not None:
            await websocket.close(4000, "Another phone is already the speaker")
            return
        self.speaker_ws = websocket
        rate = 16000
        device: dict[str, Any] = {}
        try:
            first = await websocket.recv()
            if isinstance(first, bytes):
                if self.hub_mode():
                    await websocket.close(4001, "hello required")
                    return
            else:
                hello = parse_hello(first)
                if self.hub_mode():
                    caps = hello.get("caps") or ["speaker"]
                    if "speaker" not in [str(item).lower() for item in caps]:
                        hello = {**hello, "caps": ["speaker"]}
                    ok, device = await asyncio.to_thread(authorize_hello, self.auth_url, hello)
                    if not ok:
                        await websocket.close(4001, str(device.get("error") or device.get("detail") or "unauthorized"))
                        return
                    self.speaker_device = {
                        "device_id": device.get("device_id"),
                        "device_name": device.get("device_name") or hello.get("device") or "",
                        "client": hello.get("client") or "",
                    }
                rate = int(hello.get("rate") or 16000)
                await websocket.send(json.dumps({"type": "ready", "caps": list(HUB_CAPS)}))
            await self.speaker.start_recorder(rate)
            print(f"Phone speaker connected ({rate} Hz)", flush=True)
            if self.auth_url:
                await asyncio.to_thread(
                    post_event,
                    self.auth_url,
                    {
                        "type": "speaker_connected",
                        "device_id": self.speaker_device.get("device_id"),
                        "device_name": self.speaker_device.get("device_name"),
                        "client": self.speaker_device.get("client"),
                        "rate": rate,
                    },
                )
            while True:
                chunk = await self.speaker.read_chunk()
                if not chunk:
                    if self.speaker.recorder and self.speaker.recorder.returncode is not None:
                        break
                    await asyncio.sleep(0.02)
                    continue
                await websocket.send(chunk)
        except Exception as exc:
            print(f"Speaker stream ended: {exc}", flush=True)
        finally:
            if self.speaker_ws is websocket:
                self.speaker_ws = None
            device = dict(self.speaker_device)
            self.speaker_device = {}
            await self.speaker.stop_recorder()
            if self.auth_url and device:
                await asyncio.to_thread(
                    post_event,
                    self.auth_url,
                    {
                        "type": "speaker_disconnected",
                        "device_id": device.get("device_id"),
                        "device_name": device.get("device_name"),
                        "client": device.get("client"),
                    },
                )
            print("Phone speaker disconnected", flush=True)

    async def watch_source(self) -> None:
        while True:
            await asyncio.sleep(2)
            try:
                recreated = await asyncio.to_thread(self.mic.ensure_source)
                if recreated and self.mic.player:
                    await asyncio.to_thread(self.mic._link_player)
                await asyncio.to_thread(self.speaker.ensure_sink)
            except Exception as exc:
                print(f"Source watch: {exc}", flush=True)

    async def run(self) -> None:
        self.mic.create_source()
        self.speaker.create_sink()
        if self.set_default:
            subprocess.run(["pactl", "set-default-source", SOURCE_NAME], check=False)
        ip = wait_lan_ip()
        ensure_certs(ip, self.data_dir, stable=self.stable_cert)
        cert, key, _ = cert_paths(self.data_dir)
        try:
            self.fingerprint = cert_fingerprint(cert)
        except Exception as exc:
            print(f"Could not read certificate fingerprint: {exc}", flush=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        url = f"https://{ip}:{self.port}"
        print("LanMic is ready. No ads, no time limit.", flush=True)
        print(f"1. On the phone, open  {url}", flush=True)
        print("2. Accept the certificate warning (Advanced → Proceed).", flush=True)
        print("3. Tap Start, allow the microphone, and keep the tab open.", flush=True)
        print("4. In Ubuntu, choose input device LanMic.", flush=True)
        print(f"Desktop test page: http://127.0.0.1:{self.http_port}", flush=True)
        print(f"Phone app discovery: UDP {DISCOVER_PORT}  and  http://127.0.0.1:{self.http_port}/info", flush=True)
        if self.fingerprint:
            print(f"Certificate fingerprint: {self.fingerprint}", flush=True)
        if not self.hub_mode():
            print_qr(url)
        serve_kwargs = dict(
            process_request=self.process_request,
            max_size=2**20,
            max_queue=64,
            ping_interval=20,
            ping_timeout=20,
        )
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: DiscoverProtocol(self.discover_bytes),
            local_addr=("0.0.0.0", DISCOVER_PORT),
            allow_broadcast=True,
        )
        watcher = asyncio.create_task(self.watch_source())
        try:
            async with (
                serve(self.handler, self.host, self.port, ssl=ctx, **serve_kwargs),
                serve(self.handler, self.http_host, self.http_port, **serve_kwargs),
            ):
                await asyncio.Future()
        finally:
            watcher.cancel()
            transport.close()


def install_service() -> None:
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit = unit_dir / "lanmic.service"
    venv_python = ROOT / ".venv" / "bin" / "python"
    python = str(venv_python if venv_python.exists() else Path(sys.executable).resolve())
    unit.write_text(
        f"""[Unit]
Description=LanMic phone microphone
After=pipewire.service pipewire-pulse.service network-online.target
Wants=pipewire.service

[Service]
Type=simple
WorkingDirectory={ROOT}
ExecStart={python} {ROOT / "lanmic.py"} --default --http-port 8767
Restart=on-failure
RestartSec=2
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
""",
        encoding="utf-8",
    )
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "--user", "enable", "--now", "lanmic.service"], check=True)
    print(f"Installed {unit}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Use a phone mic as a Linux microphone over Wi-Fi.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--http-port", type=int, default=8765)
    parser.add_argument("--http-host", default="0.0.0.0", help="Bind address for the plain HTTP/WS port")
    parser.add_argument("--auth-url", default="", help="Hub backend URL that authorizes phones, e.g. http://127.0.0.1:8085/api/phone-mic/internal")
    parser.add_argument("--data-dir", default="", help="Directory for the TLS certificate")
    parser.add_argument("--stable-cert", action="store_true", help="Generate the certificate once and keep it across IP changes")
    parser.add_argument("--name", default="", help="Display name advertised on the LAN")
    parser.add_argument("--hub-uuid", default="", help="Hub UUID advertised on the LAN")
    parser.add_argument("--default", action="store_true", help=f"Set {SOURCE_NAME} as the default input")
    parser.add_argument("command", nargs="?", choices=["install-service"])
    args = parser.parse_args()
    if args.command == "install-service":
        install_service()
        return 0

    server = LanMicServer(
        args.host,
        args.port,
        args.http_port,
        args.default,
        http_host=args.http_host,
        auth_url=args.auth_url,
        data_dir=Path(args.data_dir).expanduser() if args.data_dir else DEFAULT_DATA,
        stable_cert=args.stable_cert,
        name=args.name,
        hub_uuid=args.hub_uuid,
    )
    stop = asyncio.Event()

    async def run() -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        run_task = asyncio.create_task(server.run())
        await stop.wait()
        run_task.cancel()
        try:
            await run_task
        except asyncio.CancelledError:
            pass
        await server.mic.stop_player()
        server.mic.destroy_source()

    try:
        asyncio.run(run())
    finally:
        server.mic.destroy_source()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
