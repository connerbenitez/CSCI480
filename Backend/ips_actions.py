from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from datetime import datetime

import psutil


def normalize_ip(ip: str) -> str:
    return str(ipaddress.ip_address((ip or "").strip()))


def get_local_ips() -> set[str]:
    local_ips: set[str] = {"127.0.0.1", "::1"}
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                value = addr.address.split("%")[0]
                if value:
                    local_ips.add(value)
    return local_ips


def is_safe_to_block(ip: str) -> tuple[bool, str]:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return False, "Loopback addresses must not be blocked."
    if addr.is_multicast:
        return False, "Multicast addresses are not valid firewall targets."
    if addr.is_unspecified:
        return False, "Unspecified addresses are not valid firewall targets."
    if ip in get_local_ips():
        return False, "The selected IP belongs to this host."
    return True, ""


def build_rule_names(ip: str) -> tuple[str, str]:
    safe_ip = ip.replace(":", "_").replace(".", "_")
    return f"CSCI480-IPS-IN-{safe_ip}", f"CSCI480-IPS-OUT-{safe_ip}"


def _run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def block_ip(ip: str, reason: str) -> dict:
    normalized = normalize_ip(ip)
    allowed, message = is_safe_to_block(normalized)
    if not allowed:
        return {
            "success": False,
            "ip": normalized,
            "reason": reason,
            "message": message,
            "platform": platform.system(),
            "blocked_at": None,
            "commands": [],
        }

    inbound_rule, outbound_rule = build_rule_names(normalized)
    system = platform.system().lower()

    if system == "windows":
        commands = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={inbound_rule}", "dir=in", "action=block", f"remoteip={normalized}"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={outbound_rule}", "dir=out", "action=block", f"remoteip={normalized}"],
        ]
    else:
        commands = [
            ["iptables", "-I", "INPUT", "-s", normalized, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "-d", normalized, "-j", "DROP"],
        ]

    outputs = []
    success = True
    for command in commands:
        result = _run_command(command)
        outputs.append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        )
        if result.returncode != 0:
            success = False

    message = "Firewall rules created." if success else "Firewall command failed. Run the app with elevated privileges."
    return {
        "success": success,
        "applied": success,
        "ip": normalized,
        "reason": reason,
        "message": message,
        "platform": platform.system(),
        "blocked_at": datetime.utcnow().isoformat() + "Z",
        "commands": outputs,
    }


def unblock_ip(ip: str) -> dict:
    normalized = normalize_ip(ip)
    inbound_rule, outbound_rule = build_rule_names(normalized)
    system = platform.system().lower()

    if system == "windows":
        commands = [
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={inbound_rule}"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={outbound_rule}"],
        ]
    else:
        commands = [
            ["iptables", "-D", "INPUT", "-s", normalized, "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-d", normalized, "-j", "DROP"],
        ]

    outputs = []
    success = True
    for command in commands:
        result = _run_command(command)
        outputs.append(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        )
        if result.returncode != 0:
            success = False

    message = "Firewall rules removed." if success else "Failed to remove one or more firewall rules."
    return {
        "success": success,
        "applied": False,
        "ip": normalized,
        "message": message,
        "platform": platform.system(),
        "commands": outputs,
        "unblocked_at": datetime.utcnow().isoformat() + "Z",
    }
