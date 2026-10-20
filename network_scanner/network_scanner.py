#!/usr/bin/env python3
"""
Network Scanner — ARP-based host discovery.
Educational / isolated-lab use only.
"""

import argparse
import sys

import scapy.all as scapy


def scan(target: str, interface: str | None = None) -> list[dict]:
    arp = scapy.ARP(pdst=target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    kwargs: dict = {"timeout": 1, "verbose": False}
    if interface:
        kwargs["iface"] = interface
    answered, _ = scapy.srp(broadcast / arp, **kwargs)
    return [{"ip": r[1].psrc, "mac": r[1].hwsrc} for r in answered]


def print_results(hosts: list[dict]) -> None:
    if not hosts:
        print("[-] No hosts found.")
        return
    print(f"\n{'IP Address':<20} {'MAC Address'}")
    print("-" * 40)
    for host in hosts:
        print(f"{host['ip']:<20} {host['mac']}")
    print(f"\n[+] {len(hosts)} host(s) discovered.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ARP network scanner — isolated lab / educational use only."
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP or CIDR range (e.g. 192.168.1.0/24)"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface (optional; scapy auto-selects if omitted)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(f"[*] Scanning {args.target}...")
    try:
        hosts = scan(args.target, args.interface)
        print_results(hosts)
    except PermissionError:
        print("[-] Root privileges required for raw packet capture.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
