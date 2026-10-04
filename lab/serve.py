#!/usr/bin/env python3
"""Local HTTPS test servers (one port per certificate scenario).

    python lab/serve.py          (runs until Ctrl+C)

4443 valid | 4444 near expiry | 4445 expired | 4446 wrong hostname | 4447 self-signed | 4448 weak RSA
Servers listen on 127.0.0.1 only.
"""
from __future__ import annotations

import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lab.generate_certs import generate_all  # noqa: E402
from lab.scenarios import SCENARIOS, Scenario  # noqa: E402
from utils.paths import CERT_DIR  # noqa: E402

BIND_ADDRESS = "127.0.0.1"


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"CCS lab server: {self.server.title} (port {self.server.server_port})\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep the console quiet
        pass


class LabServer(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR would allow two programs to bind the same port, so keep it off there.
    allow_reuse_address = os.name != "nt"
    daemon_threads = True

    def __init__(self, address, context: ssl.SSLContext, title: str):
        self.ssl_context = context
        self.title = title
        super().__init__(address, _Handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(10)
        # The handshake happens lazily inside the worker thread, so a bad client cannot block the server.
        return self.ssl_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address

    def handle_error(self, request, client_address):
        pass  # failed handshakes are normal in this lab (clients that reject our certificates)


def _context_for(scenario: Scenario) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if scenario.key == "weak_rsa":
        # OpenSSL normally refuses to even load a 1024-bit key; the lab needs it on purpose.
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    context.load_cert_chain(CERT_DIR / f"{scenario.cert_name}.pem", CERT_DIR / f"{scenario.cert_name}.key")
    return context


def start_servers(skip_busy: bool = False) -> list:
    """Start all lab servers in background threads. Returns the started servers.
    skip_busy=True: ports that are already taken are skipped (e.g. lab servers already running)."""
    generate_all()
    started = []
    for scenario in SCENARIOS:
        if not scenario.serve:
            continue
        try:
            server = LabServer((BIND_ADDRESS, scenario.port), _context_for(scenario), scenario.title)
        except OSError as exc:
            if skip_busy:
                print(f"  port {scenario.port} already in use - assuming a lab server is running there")
                continue
            stop_servers(started)
            raise SystemExit(f"Cannot listen on port {scenario.port}: {exc}")
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
    return started


def stop_servers(servers: list) -> None:
    for server in servers:
        server.shutdown()
        server.server_close()


def main() -> int:
    servers = start_servers()
    print("CCS lab HTTPS servers running (Ctrl+C to stop):")
    for server in servers:
        print(f"  https://localhost:{server.server_port}  -  {server.title}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping lab servers.")
    stop_servers(servers)
    return 0


if __name__ == "__main__":
    sys.exit(main())
