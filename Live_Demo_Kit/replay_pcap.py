#!/usr/bin/env python3
"""
PCAP Replay Tool for Demo
CSCI480 Layered IDS/IPS - Senior Capstone Project
Replays PCAP files on the network using Scapy
"""

from scapy.all import *
import sys

def get_wifi_interface():
    """Get WiFi interface name"""
    try:
        interfaces = get_if_list()
        # Common WiFi interface names on Windows
        wifi_names = ['Wi-Fi', 'WiFi', 'Wireless', 'wlan', 'WLAN']
        for iface in interfaces:
            for wifi_name in wifi_names:
                if wifi_name.lower() in iface.lower():
                    return iface
        return interfaces[0] if interfaces else None
    except:
        return None

def replay_pcap(filename, interface=None):
    """Replay PCAP file on network interface"""
    if not os.path.exists(filename):
        print(f"[ERROR] File not found: {filename}")
        return False
    
    if interface is None:
        interface = get_wifi_interface()
        if not interface:
            print("[ERROR] No network interface found")
            return False
    
    print(f"[INFO] Replaying {filename} on interface: {interface}")
    
    try:
        packets = rdpcap(filename)
        print(f"[INFO] Loaded {len(packets)} packets from {filename}")
        
        for i, packet in enumerate(packets):
            sendp(packet, iface=interface, verbose=False)
            if (i + 1) % 10 == 0:
                print(f"[INFO] Sent {i + 1}/{len(packets)} packets...")
        
        print(f"[DONE] Successfully replayed {len(packets)} packets")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to replay PCAP: {e}")
        return False

def main():
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - PCAP REPLAY TOOL")
    print("=" * 70)
    print()
    
    if len(sys.argv) < 2:
        print("Usage: python replay_pcap.py <pcap_file>")
        print()
        print("Available PCAP files:")
        pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap')]
        if pcap_files:
            for f in pcap_files:
                print(f"  - {f}")
        else:
            print("  (No PCAP files found)")
        return
    
    filename = sys.argv[1]
    replay_pcap(filename)

if __name__ == "__main__":
    main()
