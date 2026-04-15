#!/usr/bin/env python3
"""
List available network interfaces for packet capture.
Helps identify which interface to use with test_live_network.py
"""

import sys

try:
    import psutil
except ImportError:
    print("Installing psutil...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

try:
    from scapy.all import get_if_list
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import get_if_list


def list_interfaces():
    """List all available network interfaces."""
    print("="*70)
    print("AVAILABLE NETWORK INTERFACES")
    print("="*70)
    print()
    
    interfaces = []
    
    # Try psutil first
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        
        for iface_name, if_addrs_list in sorted(if_addrs.items()):
            is_up = if_stats.get(iface_name, psutil.snicstat(isup=False)).isup
            
            # Get IP addresses
            ips = []
            mac = None
            for addr in if_addrs_list:
                if addr.family.name == 'AF_INET':
                    ips.append(f"IPv4: {addr.address}")
                elif addr.family.name == 'AF_INET6':
                    ips.append(f"IPv6: {addr.address}")
                elif addr.family.name == 'AF_LINK':
                    mac = addr.address
            
            status = "ACTIVE ✓" if is_up else "DOWN"
            
            interfaces.append({
                'name': iface_name,
                'status': status,
                'is_up': is_up,
                'ips': ips,
                'mac': mac
            })
    except Exception as e:
        print(f"Note: Could not get full interface info from psutil: {e}\n")
    
    # Display interfaces
    count = 1
    for iface in interfaces:
        print(f"{count}. {iface['name']}")
        print(f"   Status: {iface['status']}")
        if iface['mac']:
            print(f"   MAC: {iface['mac']}")
        for ip in iface['ips']:
            print(f"   {ip}")
        print()
        count += 1
    
    # Also try Scapy's list
    print("\nSecondary interface list (via Scapy):")
    try:
        scapy_ifaces = get_if_list()
        for iface in scapy_ifaces[:10]:
            print(f"  - {iface}")
        if len(scapy_ifaces) > 10:
            print(f"  ... and {len(scapy_ifaces) - 10} more")
    except Exception as e:
        print(f"  Could not retrieve: {e}")
    
    print("\n" + "="*70)
    print("USAGE")
    print("="*70)
    print("\nUse one of the interface names above with test_live_network.py:\n")
    print("  python test_live_network.py --interface \"<interface_name>\" --duration 60\n")
    print("Examples:")
    for i, iface in enumerate(interfaces[:3], 1):
        if iface['is_up']:
            print(f"  python test_live_network.py --interface \"{iface['name']}\" --duration 60")
    print()


if __name__ == '__main__':
    list_interfaces()
