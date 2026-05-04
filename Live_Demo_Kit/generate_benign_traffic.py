#!/usr/bin/env python3
"""
Generate Benign Network Traffic for Demo
CSCI480 Layered IDS/IPS - Senior Capstone Project
Educational tool for demonstrating baseline traffic detection
"""

import socket
import time
import threading
import random
from datetime import datetime

def generate_http_traffic(target_ip, target_port, duration_seconds=60):
    """Generate benign HTTP-like traffic"""
    print(f"[INFO] Generating benign HTTP traffic to {target_ip}:{target_port}")
    end_time = time.time() + duration_seconds
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, target_port))
            
            # Simulate HTTP GET request
            request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            sock.send(request.encode())
            
            # Try to receive response
            try:
                response = sock.recv(1024)
            except:
                pass
            
            sock.close()
            
            # Random delay between requests (0.5-3 seconds)
            time.sleep(random.uniform(0.5, 3.0))
            
        except Exception as e:
            print(f"[WARN] Connection failed: {e}")
            time.sleep(1)

def generate_dns_traffic(target_ip, target_port=53, duration_seconds=60):
    """Generate benign DNS-like traffic"""
    print(f"[INFO] Generating benign DNS traffic to {target_ip}:{target_port}")
    end_time = time.time() + duration_seconds
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            
            # Simulate DNS query (simplified)
            query = b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01'
            sock.sendto(query, (target_ip, target_port))
            
            try:
                response, _ = sock.recvfrom(512)
            except:
                pass
            
            sock.close()
            
            # Random delay (1-5 seconds)
            time.sleep(random.uniform(1.0, 5.0))
            
        except Exception as e:
            print(f"[WARN] DNS query failed: {e}")
            time.sleep(1)

def generate_ssh_traffic(target_ip, target_port=22, duration_seconds=60):
    """Generate benign SSH-like traffic"""
    print(f"[INFO] Generating benign SSH traffic to {target_ip}:{target_port}")
    end_time = time.time() + duration_seconds
    
    while time.time() < end_time:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, target_port))
            
            # Simulate SSH banner exchange
            try:
                banner = sock.recv(1024)
                if banner:
                    print(f"[INFO] Received banner: {banner[:50]}...")
            except:
                pass
            
            sock.close()
            
            # Random delay (2-10 seconds)
            time.sleep(random.uniform(2.0, 10.0))
            
        except Exception as e:
            print(f"[WARN] SSH connection failed: {e}")
            time.sleep(2)

if __name__ == "__main__":
    print("=" * 70)
    print("CSCI480 LAYERED IDS/IPS - BENIGN TRAFFIC GENERATOR")
    print("=" * 70)
    print()
    
    # Target localhost for demo
    target_ip = "127.0.0.1"
    duration = 60  # seconds
    
    print(f"Target: {target_ip}")
    print(f"Duration: {duration} seconds")
    print()
    
    # Start traffic generators in threads
    threads = []
    
    # HTTP traffic (port 5000 - the dashboard)
    t1 = threading.Thread(target=generate_http_traffic, args=(target_ip, 5000, duration))
    threads.append(t1)
    
    # DNS traffic (port 53)
    t2 = threading.Thread(target=generate_dns_traffic, args=(target_ip, 53, duration))
    threads.append(t2)
    
    # SSH traffic (port 22)
    t3 = threading.Thread(target=generate_ssh_traffic, args=(target_ip, 22, duration))
    threads.append(t3)
    
    print("[INFO] Starting benign traffic generation...")
    print("[INFO] Press Ctrl+C to stop early")
    print()
    
    for t in threads:
        t.start()
    
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[INFO] Traffic generation stopped by user")
    
    print()
    print("[INFO] Benign traffic generation complete")
