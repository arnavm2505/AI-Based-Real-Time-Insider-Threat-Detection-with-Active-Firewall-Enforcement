from __future__ import annotations

import argparse
import csv
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_SITE_PATH = PROJECT_ROOT / "Test Site"
RULES_PATH = PROJECT_ROOT / "data" / "firewall_rules.csv"


def _active_blocked_clients(port: int) -> set[str]:
    if not RULES_PATH.exists() or RULES_PATH.stat().st_size == 0:
        return set()

    blocked: set[str] = set()
    with RULES_PATH.open("r", newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            if row.get("status") != "active":
                continue
            rule_port = str(row.get("port", "")).strip()
            if rule_port and rule_port != str(port):
                continue
            if row.get("action") not in {"block", "quarantine"}:
                continue
            source_ip = str(row.get("source_ip", "")).strip()
            if source_ip:
                blocked.add(source_ip)
    return blocked


class FirewallAwareHandler(SimpleHTTPRequestHandler):
    protected_port = 8080

    def do_GET(self) -> None:
        client_ip = str(self.client_address[0])
        if client_ip in _active_blocked_clients(self.protected_port):
            self.send_response(403)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"<!doctype html><title>Blocked</title>"
                b"<h1>Access blocked</h1>"
                b"<p>The AI firewall has blocked this client from the protected test site.</p>"
            )
            return
        super().do_GET()


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local Test Site for client PCs.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    FirewallAwareHandler.protected_port = args.port
    handler = partial(FirewallAwareHandler, directory=str(TEST_SITE_PATH))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving Test Site at http://{args.host}:{args.port}")
    print(f"Directory: {TEST_SITE_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Test Site server stopped.")


if __name__ == "__main__":
    main()
