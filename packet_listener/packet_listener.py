#!/usr/bin/env python3
"""
HTTP Packet Listener — displays cleartext HTTP requests on the local network.
Educational / isolated-lab use only.
Do NOT capture traffic on networks you do not own or have permission to monitor.
"""

import argparse
import sys

import scapy.all as scapy
from scapy.layers import http


def analyze_packet(packet: scapy.Packet) -> None:
    if not packet.haslayer(http.HTTPRequest):
        return

    req = packet[http.HTTPRequest]
    method = req.Method.decode(errors="replace") if req.Method else "?"
    host = req.Host.decode(errors="replace") if req.Host else "?"
    path = req.Path.decode(errors="replace") if req.Path else "/"

    print(f"\n[HTTP] {method} http://{host}{path}")

    if packet.haslayer(scapy.Raw):
        body = packet[scapy.Raw].load.decode(errors="replace")
        if body:
            print(f"       Body: {body[:200]}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP packet listener — isolated lab / educational use only."
    )
    parser.add_argument(
        "-i", "--interface", required=True,
        help="Network interface to listen on (e.g. eth0)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(f"[*] Listening on {args.interface} for HTTP traffic. Ctrl+C to stop.")
    try:
        scapy.sniff(iface=args.interface, store=False, prn=analyze_packet)
    except PermissionError:
        print("[-] Root privileges required for packet capture.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")


if __name__ == "__main__":
    main()
