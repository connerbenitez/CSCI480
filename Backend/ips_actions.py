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


def build_inbound_rule_name(ip: str) -> str:
    safe_ip = ip.replace(":", "_").replace(".", "_")
    return f"CSCI480-IPS-IN-ONLY-{safe_ip}"


def build_shield_rule_name(port: int, proto: str = "TCP") -> str:
    safe_proto = str(proto or "TCP").upper()
    return f"CSCI480-IPS-SHIELD-{safe_proto}-{int(port)}"


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
        "response_method": "block_bidirectional",
        "reason": reason,
        "message": message,
        "platform": platform.system(),
        "blocked_at": datetime.utcnow().isoformat() + "Z",
        "commands": outputs,
    }


def unblock_ip(ip: str) -> dict:
    normalized = normalize_ip(ip)
    inbound_rule, outbound_rule = build_rule_names(normalized)
    inbound_only_rule = build_inbound_rule_name(normalized)
    system = platform.system().lower()

    if system == "windows":
        commands = [
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={inbound_rule}"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={outbound_rule}"],
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={inbound_only_rule}"],
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
        "response_method": "unblock",
        "message": message,
        "platform": platform.system(),
        "commands": outputs,
        "unblocked_at": datetime.utcnow().isoformat() + "Z",
    }


def block_ip_inbound(ip: str, reason: str) -> dict:
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

    inbound_rule = build_inbound_rule_name(normalized)
    system = platform.system().lower()

    if system == "windows":
        commands = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={inbound_rule}", "dir=in", "action=block", f"remoteip={normalized}"],
        ]
    else:
        commands = [
            ["iptables", "-I", "INPUT", "-s", normalized, "-j", "DROP"],
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

    message = "Inbound firewall rule created." if success else "Firewall command failed. Run the app with elevated privileges."
    return {
        "success": success,
        "applied": success,
        "ip": normalized,
        "response_method": "block_inbound",
        "reason": reason,
        "message": message,
        "platform": platform.system(),
        "blocked_at": datetime.utcnow().isoformat() + "Z",
        "commands": outputs,
    }


def shield_local_port(port: int, proto: str = "TCP", reason: str = "Shielded local service port") -> dict:
    normalized_proto = str(proto or "TCP").upper()
    if normalized_proto not in {"TCP", "UDP"}:
        return {
            "success": False,
            "port": int(port),
            "proto": normalized_proto,
            "reason": reason,
            "message": "Only TCP and UDP service-port shielding are supported.",
            "commands": [],
            "shielded_at": None,
        }

    local_port = int(port)
    if local_port <= 0 or local_port > 65535:
        return {
            "success": False,
            "port": local_port,
            "proto": normalized_proto,
            "reason": reason,
            "message": "Invalid local service port.",
            "commands": [],
            "shielded_at": None,
        }

    rule_name = build_shield_rule_name(local_port, normalized_proto)
    system = platform.system().lower()

    if system == "windows":
        commands = [
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"protocol={normalized_proto}",
                f"localport={local_port}",
            ],
        ]
    else:
        commands = [
            ["iptables", "-I", "INPUT", "-p", normalized_proto.lower(), "--dport", str(local_port), "-j", "DROP"],
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

    message = "Local service port shield enabled." if success else "Firewall command failed. Run the app with elevated privileges."
    return {
        "success": success,
        "applied": success,
        "response_method": "shield_service_port",
        "port": local_port,
        "proto": normalized_proto,
        "reason": reason,
        "message": message,
        "platform": platform.system(),
        "shielded_at": datetime.utcnow().isoformat() + "Z",
        "commands": outputs,
    }


def unshield_local_port(port: int, proto: str = "TCP") -> dict:
    normalized_proto = str(proto or "TCP").upper()
    local_port = int(port)
    rule_name = build_shield_rule_name(local_port, normalized_proto)
    system = platform.system().lower()

    if system == "windows":
        commands = [
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
        ]
    else:
        commands = [
            ["iptables", "-D", "INPUT", "-p", normalized_proto.lower(), "--dport", str(local_port), "-j", "DROP"],
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

    message = "Local service port shield removed." if success else "Failed to remove one or more shield rules."
    return {
        "success": success,
        "applied": False,
        "response_method": "unshield_service_port",
        "port": local_port,
        "proto": normalized_proto,
        "message": message,
        "platform": platform.system(),
        "commands": outputs,
        "unshielded_at": datetime.utcnow().isoformat() + "Z",
    }
