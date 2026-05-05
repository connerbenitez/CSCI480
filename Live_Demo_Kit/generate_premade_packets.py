#!/usr/bin/env python3
"""
Generate Premade Attack Packets for Demo
CSCI480 Layered IDS/IPS - Senior Capstone Project
Uses Scapy to generate attack traffic patterns
"""

from scapy.all import *
import time
import random

def generate_syn_flood(target_ip, target_port, count=100):
    """Generate SYN flood packets"""
    print(f"[INFO] Generating {count} SYN flood packets to {target_ip}:{target_port}")
    for i in range(count):
        send(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), verbose=False)
    print(f"[DONE] Sent {count} SYN flood packets")

def generate_udp_flood(target_ip, target_port, count=100):
    """Generate UDP flood packets"""
    print(f"[INFO] Generating {count} UDP flood packets to {target_ip}:{target_port}")
    for i in range(count):
        send(IP(dst=target_ip)/UDP(dport=target_port)/Raw(b"test data"), verbose=False)
    print(f"[DONE] Sent {count} UDP flood packets")

def generate_http_flood(target_ip, target_port, count=50):
    """Generate HTTP flood packets"""
    print(f"[INFO] Generating {count} HTTP flood packets to {target_ip}:{target_port}")
    for i in range(count):
        send(IP(dst=target_ip)/TCP(dport=target_port, flags="S")/Raw(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"), verbose=False)
    print(f"[DONE] Sent {count} HTTP flood packets")

def generate_port_scan(target_ip, ports):
    """Generate port scan traffic"""
    print(f"[INFO] Generating port scan traffic to {target_ip}")
    for port in ports:
        send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=False)
    print(f"[DONE] Sent scan packets to {len(ports)} ports")

def main():
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - PREMADE PACKET GENERATOR")
    print("=" * 70)
    print()
    
    target_ip = "127.0.0.1"  # Localhost for demo
    
    print("Choose packet type:")
    print("1. SYN Flood (port 80)")
    print("2. UDP Flood (port 53)")
    print("3. HTTP Flood (port 80)")
    print("4. Port Scan (common ports)")
    print("5. All of the above")
    print()
    
    try:
        choice = input("Enter choice (1-5): ").strip()
        
        if choice == "1":
            generate_syn_flood(target_ip, 80, count=100)
        elif choice == "2":
            generate_udp_flood(target_ip, 53, count=100)
        elif choice == "3":
            generate_http_flood(target_ip, 80, count=50)
        elif choice == "4":
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306]
            generate_port_scan(target_ip, common_ports)
        elif choice == "5":
            print("[INFO] Generating all packet types...")
            generate_port_scan(target_ip, [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306])
            time.sleep(1)
            generate_syn_flood(target_ip, 80, count=50)
            time.sleep(1)
            generate_udp_flood(target_ip, 53, count=50)
            time.sleep(1)
            generate_http_flood(target_ip, 80, count=30)
        else:
            print("[INFO] Invalid choice")
            
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
