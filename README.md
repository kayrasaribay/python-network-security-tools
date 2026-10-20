# Python Network Security Tools

A collection of small network security tools written in Python 3 with Scapy,
built while learning ethical hacking concepts. Each tool was developed for
**educational purposes in an isolated lab environment only**.

> ⚠️ **Ethics notice:** These tools must only be used on networks and devices
> you own or have explicit written permission to test. Unauthorized use is
> illegal and unethical. All testing was performed in an isolated virtual lab.

---

## Tools

### 1. ARP Spoofer (`arp_spoofer/`)
Performs ARP poisoning between a target host and its gateway.
Restores ARP tables automatically on exit (Ctrl+C).

```bash
python3 arp_spoofer/arp_spoofer.py -t <target_ip> -g <gateway_ip>
```

### 2. Network Scanner (`network_scanner/`)
Discovers live hosts on a subnet using ARP broadcasts.
Displays IP and MAC address of each responding host.

```bash
python3 network_scanner/network_scanner.py -t 192.168.1.0/24
python3 network_scanner/network_scanner.py -t 192.168.1.0/24 -i eth0
```

### 3. HTTP Packet Listener (`packet_listener/`)
Sniffs cleartext HTTP traffic and prints request method, host, path and body.

```bash
python3 packet_listener/packet_listener.py -i eth0
```

---

## Setup

```bash
pip install -r requirements.txt
```

Requires Python 3.10+. Root privileges are required for raw packet capture.

---

## Related

- [MAC_changer](https://github.com/kayrasaribay/MAC_changer) — MAC address
  changer for Linux network interfaces (separate repository)

---

## Attribution

Tools were tested exclusively
in an isolated virtual lab (Kali Linux VM + Metasploitable).
