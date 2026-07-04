"""Client-side network logger for the AI firewall demo.

Run this on each client PC that accesses the server PC's Test Site.

Example:
    python scripts/client_logger.py --server-api http://SERVER_IP:8001/api/events --test-site-host SERVER_IP --test-site-port 8080 --client-id client1

Optional traffic probe for demos:
    python scripts/client_logger.py --server-api http://SERVER_IP:8001/api/events --test-site-host SERVER_IP --test-site-port 8080 --client-id client1 --probe-test-site

Notes:
    - Install psutil for better connection visibility: python -m pip install psutil
    - Run PowerShell as Administrator on Windows for complete connection data.
    - The timestamp is generated on the client PC before upload.
"""

from __future__ import annotations

import argparse
import getpass
import json
import socket
import time
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    import psutil
except ImportError:
    psutil = None


def resolve_host(host: str) -> set[str]:
    addresses = {host}
    try:
        for item in socket.getaddrinfo(host, None):
            addresses.add(str(item[4][0]))
    except socket.gaierror:
        pass
    return addresses


def local_ip_for_remote(host: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        return str(sock.getsockname()[0])
    except OSError:
        return socket.gethostbyname(socket.gethostname())
    finally:
        sock.close()


def post_events(server_api: str, events: list[dict[str, Any]]) -> int:
    if not events:
        return 0

    request = Request(
        server_api,
        data=json.dumps({"events": events}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        print(f"Unable to upload client events: {error}")
        return 0

    return int(payload.get("accepted", 0))


def probe_test_site(host: str, port: int) -> None:
    try:
        with urlopen(f"http://{host}:{port}", timeout=3) as response:
            response.read(512)
    except (HTTPError, URLError, TimeoutError, OSError):
        pass


def collect_matching_connections(
    test_site_host: str,
    test_site_port: int,
    client_id: str,
    seen_connections: set[tuple[Any, ...]],
) -> list[dict[str, Any]]:
    destination_addresses = resolve_host(test_site_host)
    local_ip = local_ip_for_remote(test_site_host, test_site_port)
    username = getpass.getuser()
    timestamp = datetime.now().replace(microsecond=0).isoformat()

    if psutil is None:
        return [
            {
                "timestamp": timestamp,
                "user_id": f"{client_id}:{username}",
                "source_ip": local_ip,
                "destination_ip": test_site_host,
                "protocol": "HTTP",
                "action": f"test_site_access_port_{test_site_port}",
                "bytes_sent": 18000,
                "bytes_received": 9000,
            }
        ]

    rows: list[dict[str, Any]] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, psutil.Error, OSError) as error:
        print(f"Unable to read client connections: {error}")
        return rows

    io_counters = psutil.net_io_counters()
    for connection in connections:
        remote = connection.raddr
        local = connection.laddr
        if not remote or not local:
            continue

        remote_ip = str(getattr(remote, "ip", "") or remote[0])
        remote_port = int(getattr(remote, "port", None) or remote[1])
        if remote_port != test_site_port or remote_ip not in destination_addresses:
            continue

        local_conn_ip = str(getattr(local, "ip", "") or local[0])
        local_port = int(getattr(local, "port", None) or local[1])
        signature = (local_conn_ip, local_port, remote_ip, remote_port, connection.status)
        if signature in seen_connections:
            continue

        seen_connections.add(signature)
        rows.append(
            {
                "timestamp": timestamp,
                "user_id": f"{client_id}:{username}",
                "source_ip": local_conn_ip or local_ip,
                "destination_ip": remote_ip,
                "protocol": "HTTP",
                "action": f"test_site_access_port_{test_site_port}",
                "bytes_sent": max(18000, int(io_counters.bytes_sent // 1000)),
                "bytes_received": max(9000, int(io_counters.bytes_recv // 1000)),
            }
        )

    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Send client PC test-site access logs to the AI firewall backend.")
    parser.add_argument("--server-api", required=True, help="Backend endpoint, for example http://SERVER_IP:8001/api/events")
    parser.add_argument("--test-site-host", required=True, help="Server PC IP/hostname that hosts the Test Site")
    parser.add_argument("--test-site-port", type=int, default=8080, help="Test Site HTTP port")
    parser.add_argument("--client-id", default=socket.gethostname(), help="Client label shown in the dashboard")
    parser.add_argument("--interval", type=int, default=3, help="Polling interval in seconds")
    parser.add_argument("--probe-test-site", action="store_true", help="Generate a small HTTP request each interval")
    args = parser.parse_args()

    seen_connections: set[tuple[Any, ...]] = set()
    print("Client logger started. Press Ctrl+C to stop.")
    print(f"Posting to: {args.server_api}")
    print(f"Watching: http://{args.test_site_host}:{args.test_site_port}")

    try:
        while True:
            if args.probe_test_site:
                probe_test_site(args.test_site_host, args.test_site_port)
            events = collect_matching_connections(
                args.test_site_host,
                args.test_site_port,
                args.client_id,
                seen_connections,
            )
            accepted = post_events(args.server_api, events)
            if accepted:
                print(f"Uploaded {accepted} client event(s) at {datetime.now().isoformat(timespec='seconds')}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Client logger stopped.")


if __name__ == "__main__":
    main()
