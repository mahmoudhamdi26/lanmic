#!/usr/bin/env python3
"""LanMic: stream a phone microphone into a PipeWire virtual mic over Wi-Fi."""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time
from http import HTTPStatus
from pathlib import Path

from websockets.asyncio.server import ServerConnection, serve
from websockets.http11 import Request, Response

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
DATA = Path.home() / ".local" / "share" / "lanmic"
CERT = DATA / "cert.pem"
KEY = DATA / "key.pem"
CERT_IP = DATA / "ip.txt"
SOURCE_NAME = "LanMic"
BRIDGE_NAME = "LanMicBridge"
DEFAULT_PORT = 8766


def lan_ip() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 80))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def ensure_certs(ip: str) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    if CERT.exists() and KEY.exists() and CERT_IP.exists() and CERT_IP.read_text().strip() == ip:
        return
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "825",
            "-nodes", "-keyout", str(KEY), "-out", str(CERT), "-subj", "/CN=LanMic",
            "-addext", f"subjectAltName=IP:{ip},IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    CERT_IP.write_text(ip + "\n", encoding="utf-8")
    print(f"Created TLS certificate for {ip}", flush=True)


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
        if BRIDGE_NAME not in names:
            self.module_ids.append(load_module([
                "module-null-sink",
                f"sink_name={BRIDGE_NAME}",
                f"sink_properties=device.description={BRIDGE_NAME}",
                "channel_map=mono",
            ]))
        if SOURCE_NAME not in pactl_names("sources"):
            self.module_ids.append(load_module([
                "module-null-sink",
                "media.class=Audio/Source/Virtual",
                f"sink_name={SOURCE_NAME}",
                f"sink_properties=device.description={SOURCE_NAME}",
                "channel_map=mono",
            ]))
        self._link_bridge()
        print(f"PipeWire source {SOURCE_NAME} ready", flush=True)

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
            outputs = [p for p in pw_ports("output") if p.startswith("pw-cat:output")]
            if outputs:
                inputs = [p for p in pw_ports("input") if p.startswith(f"{SOURCE_NAME}:input")]
                dest = inputs[0] if inputs else f"{SOURCE_NAME}:input_MONO"
                for src in outputs:
                    link_ports(src, dest)
                print(f"Routed phone audio directly into {SOURCE_NAME}", flush=True)
                return
            time.sleep(0.05)
        print("Warning: pw-cat ports not found", flush=True)

    async def start_player(self, rate: int) -> None:
        await self.stop_player()
        self.bytes_in = 0
        self.peak = 0
        self.last_log = time.monotonic()
        self.player = await asyncio.create_subprocess_exec(
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
            "-P", "node.dont-fallback=true",
            "-P", f"node.latency=256/{rate}",
            "-",
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


class LanMicServer:
    def __init__(self, host: str, port: int, http_port: int, set_default: bool) -> None:
        self.host = host
        self.port = port
        self.http_port = http_port
        self.set_default = set_default
        self.mic = PipeWireMic()
        self.active: ServerConnection | None = None
        self.static = {
            "/": (WEB / "index.html", "text/html; charset=utf-8"),
            "/index.html": (WEB / "index.html", "text/html; charset=utf-8"),
            "/manifest.json": (WEB / "manifest.json", "application/manifest+json"),
        }

    def process_request(self, connection: ServerConnection, request: Request) -> Response | None:
        path = request.path.split("?", 1)[0]
        if path == "/ws":
            return None
        if path == "/status":
            body = json.dumps(
                {
                    "source": SOURCE_NAME,
                    "connected": self.active is not None,
                    "playing": self.mic.player is not None,
                    "bytes": self.mic.bytes_in,
                    "peak": self.mic.peak,
                }
            )
            response = connection.respond(HTTPStatus.OK, body)
            response.headers["Content-Type"] = "application/json"
            return response
        asset = self.static.get(path)
        if not asset:
            return connection.respond(HTTPStatus.NOT_FOUND, "Not found")
        path_obj, content_type = asset
        response = connection.respond(HTTPStatus.OK, path_obj.read_text(encoding="utf-8"))
        response.headers["Content-Type"] = content_type
        response.headers["Cache-Control"] = "no-store"
        return response

    async def handler(self, websocket: ServerConnection) -> None:
        if self.active is not None:
            await websocket.close(4000, "Another phone is already streaming")
            return
        self.active = websocket
        rate = 48000
        try:
            first = await websocket.recv()
            if isinstance(first, bytes):
                await self.mic.start_player(rate)
                await self.mic.write(first)
            else:
                hello = json.loads(first)
                rate = int(hello.get("rate") or 48000)
                await self.mic.start_player(rate)
            print(f"Phone connected ({rate} Hz)", flush=True)
            async for message in websocket:
                if isinstance(message, bytes):
                    await self.mic.write(message)
        except Exception as exc:
            print(f"Stream ended: {exc}", flush=True)
        finally:
            if self.active is websocket:
                self.active = None
            await self.mic.stop_player()
            print("Phone disconnected", flush=True)

    async def run(self) -> None:
        self.mic.create_source()
        if self.set_default:
            subprocess.run(["pactl", "set-default-source", SOURCE_NAME], check=False)
        ip = lan_ip()
        ensure_certs(ip)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        url = f"https://{ip}:{self.port}"
        print("LanMic is ready. No ads, no time limit.", flush=True)
        print(f"1. On the phone, open  {url}", flush=True)
        print("2. Accept the certificate warning (Advanced → Proceed).", flush=True)
        print("3. Tap Start, allow the microphone, and keep the tab open.", flush=True)
        print("4. In Ubuntu, choose input device LanMic.", flush=True)
        print(f"Desktop test page: http://127.0.0.1:{self.http_port}", flush=True)
        print_qr(url)
        serve_kwargs = dict(
            process_request=self.process_request,
            max_size=2**20,
            max_queue=64,
            ping_interval=20,
            ping_timeout=20,
        )
        async with (
            serve(self.handler, self.host, self.port, ssl=ctx, **serve_kwargs),
            serve(self.handler, self.host, self.http_port, **serve_kwargs),
        ):
            await asyncio.Future()


def install_service() -> None:
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit = unit_dir / "lanmic.service"
    venv_python = ROOT / ".venv" / "bin" / "python"
    python = str(venv_python if venv_python.exists() else Path(sys.executable).resolve())
    unit.write_text(
        f"""[Unit]
Description=LanMic phone microphone
After=pipewire.service pipewire-pulse.service
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
    parser.add_argument("--default", action="store_true", help=f"Set {SOURCE_NAME} as the default input")
    parser.add_argument("command", nargs="?", choices=["install-service"])
    args = parser.parse_args()
    if args.command == "install-service":
        install_service()
        return 0

    server = LanMicServer(args.host, args.port, args.http_port, args.default)
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
