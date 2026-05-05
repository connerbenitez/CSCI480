#!/usr/bin/env python3
"""
Generate PCAP Files for Demo Attack Scenarios
CSCI480 Layered IDS/IPS - Senior Capstone Project
Creates PCAP files that can be loaded into Capsa or other packet analysis tools
"""

from scapy.all import *
import time

def create_port_scan_pcap(filename="port_scan.pcap"):
    """Create PCAP file with port scan traffic"""
    print(f"[INFO] Creating port scan PCAP: {filename}")
    packets = []
    target_ip = "192.168.1.100"
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306]
    
    for port in common_ports:
        # SYN packet
        packets.append(IP(dst=target_ip)/TCP(dport=port, flags="S"))
        # ACK packet (complete handshake)
        packets.append(IP(dst=target_ip)/TCP(dport=port, flags="A"))
    
    wrpcap(filename, packets)
    print(f"[DONE] Created {filename} with {len(packets)} packets")

def create_syn_flood_pcap(filename="syn_flood.pcap"):
    """Create PCAP file with SYN flood attack"""
    print(f"[INFO] Creating SYN flood PCAP: {filename}")
    packets = []
    target_ip = "192.168.1.100"
    target_port = 80
    
    for i in range(200):
        packets.append(IP(dst=target_ip, src=f"192.168.1.{i % 255}")/TCP(dport=target_port, flags="S", sport=12345+i))
    
    wrpcap(filename, packets)
    print(f"[DONE] Created {filename} with {len(packets)} packets")

def create_udp_flood_pcap(filename="udp_flood.pcap"):
    """Create PCAP file with UDP flood attack"""
    print(f"[INFO] Creating UDP flood PCAP: {filename}")
    packets = []
    target_ip = "192.168.1.100"
    target_port = 53
    
    for i in range(200):
        packets.append(IP(dst=target_ip, src=f"192.168.1.{i % 255}")/UDP(dport=target_port, sport=54321+i)/Raw(b"test data"))
    
    wrpcap(filename, packets)
    print(f"[DONE] Created {filename} with {len(packets)} packets")

def create_http_flood_pcap(filename="http_flood.pcap"):
    """Create PCAP file with HTTP flood attack"""
    print(f"[INFO] Creating HTTP flood PCAP: {filename}")
    packets = []
    target_ip = "192.168.1.100"
    target_port = 80
    
    for i in range(100):
        http_request = b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"
        packets.append(IP(dst=target_ip, src=f"192.168.1.{i % 255}")/TCP(dport=target_port, flags="PA", sport=54321+i)/Raw(http_request))
    
    wrpcap(filename, packets)
    print(f"[DONE] Created {filename} with {len(packets)} packets")

def create_benign_traffic_pcap(filename="benign_traffic.pcap"):
    """Create PCAP file with benign traffic"""
    print(f"[INFO] Creating benign traffic PCAP: {filename}")
    packets = []
    
    # Normal HTTP traffic
    for i in range(20):
        http_request = b"GET /page.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        packets.append(IP(dst="192.168.1.100")/TCP(dport=80, flags="PA", sport=54321+i)/Raw(http_request))
    
    # Normal DNS traffic
    for i in range(10):
        packets.append(IP(dst="192.168.1.100")/UDP(dport=53, sport=54321+i)/Raw(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"))
    
    wrpcap(filename, packets)
    print(f"[DONE] Created {filename} with {len(packets)} packets")

def create_mixed_attack_pcap(filename="mixed_attack.pcap"):
    """Create PCAP file with mixed attack patterns"""
    print(f"[INFO] Creating mixed attack PCAP: {filename}")
    packets = []
    target_ip = "192.168.1.100"
    
    # Port scan
    for port in [21, 22, 23, 25, 53, 80, 443]:
        packets.append(IP(dst=target_ip)/TCP(dport=port, flags="S"))
    
    # SYN flood
    for i in range(50):
        packets.append(IP(dst=target_ip, src=f"192.168.1.{i % 255}")/TCP(dport=80, flags="S", sport=12345+i))
    
    # UDP flood
    for i in range(30):
        packets.append(IP(dst=target_ip, src=f"192.168.1.{(i+50) % 255}")/UDP(dport=53, sport=54321+i)/Raw(b"test data"))
    
    wrpcap(filename, packets)
    print(f"[DONE] Created {filename} with {len(packets)} packets")

def main():
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - PCAP FILE GENERATOR")
    print("=" * 70)
    print()
    print("This script creates PCAP files for different attack scenarios.")
    print("These files can be loaded into Capsa, Wireshark, or other packet tools.")
    print()
    
    print("Choose PCAP file to create:")
    print("1. Port Scan (port_scan.pcap)")
    print("2. SYN Flood (syn_flood.pcap)")
    print("3. UDP Flood (udp_flood.pcap)")
    print("4. HTTP Flood (http_flood.pcap)")
    print("5. Benign Traffic (benign_traffic.pcap)")
    print("6. Mixed Attack (mixed_attack.pcap)")
    print("7. Create All PCAP Files")
    print()
    
    try:
        choice = input("Enter choice (1-7): ").strip()
        
        if choice == "1":
            create_port_scan_pcap()
        elif choice == "2":
            create_syn_flood_pcap()
        elif choice == "3":
            create_udp_flood_pcap()
        elif choice == "4":
            create_http_flood_pcap()
        elif choice == "5":
            create_benign_traffic_pcap()
        elif choice == "6":
            create_mixed_attack_pcap()
        elif choice == "7":
            print("[INFO] Creating all PCAP files...")
            create_port_scan_pcap()
            create_syn_flood_pcap()
            create_udp_flood_pcap()
            create_http_flood_pcap()
            create_benign_traffic_pcap()
            create_mixed_attack_pcap()
            print("[DONE] All PCAP files created!")
        else:
            print("[INFO] Invalid choice")
            
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
