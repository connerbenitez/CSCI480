#!/usr/bin/env python3
"""
Simulate Port Scan Behavior for Demo
CSCI480 Layered IDS/IPS - Senior Capstone Project
Educational tool for demonstrating port scan detection
"""

import socket
import time
import random
from datetime import datetime

def simulate_port_scan(target_ip, start_port=1, end_port=1024, scan_type="SYN"):
    """
    Simulate port scanning behavior
    Safe: Only scans localhost by default, generates traffic patterns
    """
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - PORT SCAN SIMULATOR")
    print("=" * 70)
    print()
    print(f"Target: {target_ip}")
    print(f"Port Range: {start_port}-{end_port}")
    print(f"Scan Type: {scan_type}")
    print()
    print("[INFO] Starting port scan simulation...")
    print("[INFO] This generates traffic patterns resembling port scans")
    print("[INFO] Press Ctrl+C to stop early")
    print()
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080, 8443]
    
    try:
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                
                # Attempt connection
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    print(f"[OPEN] Port {port} is open")
                else:
                    print(f"[CLOSED] Port {port} is closed")
                
                sock.close()
                
                # Small delay to avoid overwhelming the system
                time.sleep(0.1)
                
            except Exception as e:
                print(f"[ERROR] Port {port}: {e}")
                time.sleep(0.1)
        
        print()
        print("[INFO] Port scan simulation complete")
        
    except KeyboardInterrupt:
        print("\n[INFO] Port scan stopped by user")

def simulate_slow_scan(target_ip, duration_seconds=60):
    """
    Simulate a slower, stealthier port scan
    Generates traffic over a longer period
    """
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - STEALTH SCAN SIMULATOR")
    print("=" * 70)
    print()
    print(f"Target: {target_ip}")
    print(f"Duration: {duration_seconds} seconds")
    print()
    print("[INFO] Starting stealthy port scan simulation...")
    print("[INFO] This generates intermittent scan-like traffic")
    print("[INFO] Press Ctrl+C to stop early")
    print()
    
    common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 8080]
    end_time = time.time() + duration_seconds
    
    try:
        while time.time() < end_time:
            # Scan a random port
            port = random.choice(common_ports)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((target_ip, port))
                sock.close()
                
                print(f"[SCAN] Checked port {port}")
                
            except Exception as e:
                pass
            
            # Random delay (1-5 seconds) to appear stealthy
            time.sleep(random.uniform(1.0, 5.0))
        
        print()
        print("[INFO] Stealth scan simulation complete")
        
    except KeyboardInterrupt:
        print("\n[INFO] Stealth scan stopped by user")

if __name__ == "__main__":
    import sys
    
    target = "127.0.0.1"  # Default to localhost
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    
    print("Choose scan type:")
    print("1. Fast scan (common ports only)")
    print("2. Stealth scan (slow, intermittent)")
    print()
    
    try:
        choice = input("Enter choice (1-2): ").strip()
        
        if choice == "1":
            simulate_port_scan(target)
        elif choice == "2":
            simulate_slow_scan(target, duration_seconds=60)
        else:
            print("[INFO] Invalid choice, running fast scan")
            simulate_port_scan(target)
            
    except KeyboardInterrupt:
        print("\n[INFO] Exiting")
