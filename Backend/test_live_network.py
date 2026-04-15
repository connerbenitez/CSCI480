#!/usr/bin/env python3
"""
Capture live traffic, optionally generate a real attack during capture,
and save ML detection results to CSV.
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import MODELS, PREDICT_ALL, feature_rows_from_packets
from attack_simulator import available_attack_types, simulate_attack

try:
    from scapy.all import sniff
except ImportError as exc:
    print(f"Scapy is required: {exc}")
    sys.exit(1)


def run_attack_after_delay(args):
    time.sleep(args.attack_delay)
    print(f"[attack] launching {args.generate_attack} against {args.target_ip}")
    result = simulate_attack(
        attack_type=args.generate_attack,
        target_ip=args.target_ip,
        packet_count=args.attack_count,
        target_port=args.target_port,
        start_port=args.target_port,
    )
    print(f"[attack] sent {result['packet_count']} packets in {result['duration_seconds']}s")


def main():
    parser = argparse.ArgumentParser(description="Run a live IDS/IPS test capture.")
    parser.add_argument("--interface", "-i", default="Wi-Fi", help="Interface to capture on")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("--output", "-o", default="live_test_results.csv", help="CSV output path")
    parser.add_argument("--generate-attack", choices=sorted(available_attack_types()), help="Generate a real attack during capture")
    parser.add_argument("--target-ip", default="127.0.0.1", help="Attack target IP")
    parser.add_argument("--target-port", type=int, default=80, help="Target port or start port")
    parser.add_argument("--attack-count", type=int, default=40, help="Packets to send when generating an attack")
    parser.add_argument("--attack-delay", type=float, default=3.0, help="Seconds to wait before launching the attack")
    args = parser.parse_args()

    if MODELS is None or PREDICT_ALL is None:
        print("ML models failed to load. Start by fixing the backend model dependencies.")
        sys.exit(1)

    if args.generate_attack:
        worker = threading.Thread(target=run_attack_after_delay, args=(args,), daemon=True)
        worker.start()

    print(f"Capturing on {args.interface} for {args.duration} seconds...")
    packets = sniff(
        iface=args.interface,
        filter="ip and not (dst host 255.255.255.255 or dst net 224.0.0.0/4)",
        timeout=args.duration,
    )
    print(f"Captured {len(packets)} packets")

    rows = feature_rows_from_packets(packets)
    if not rows:
        print("No flows were large enough to score.")
        sys.exit(1)

    predictions = PREDICT_ALL(MODELS, pd.DataFrame(rows))
    combined = []
    for row, pred in zip(rows, predictions):
        combined.append({**row, **pred})

    output_path = Path(args.output)
    pd.DataFrame(combined).to_csv(output_path, index=False)
    print(f"Saved {len(combined)} scored flows to {output_path}")


if __name__ == "__main__":
    main()
