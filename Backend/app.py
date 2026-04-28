from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import Counter, deque
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path

import numpy as np
import pandas as pd
import psutil
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

try:
    from scapy.all import Ether, IP, PcapReader, Raw, TCP, UDP, rdpcap, send, sendp, sniff
except ImportError:  # pragma: no cover
    Ether = IP = PcapReader = Raw = TCP = UDP = rdpcap = send = sendp = sniff = None


def resource_root() -> Path:
    if getattr(sys, "frozen", False):
        meipass = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        exe_dir = Path(sys.executable).resolve().parent
        for candidate in (meipass, exe_dir / "_internal", exe_dir):
            if (candidate / "Frontend" / "index.html").exists() and (candidate / "ML").exists():
                return candidate
        return meipass
    return Path(__file__).resolve().parent.parent


def runtime_root() -> Path:
    if getattr(sys, "frozen", False):
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        root = base / "CSCI480LayeredIDS"
        root.mkdir(parents=True, exist_ok=True)
        return root
    return Path(__file__).resolve().parent


RESOURCE_ROOT = resource_root()
BASE_DIR = RESOURCE_ROOT
BACKEND_DIR = RESOURCE_ROOT / "Backend"
FRONTEND_DIR = RESOURCE_ROOT / "Frontend"
RUNTIME_DIR = runtime_root()
os.environ["CSCI480_ML_ROOT"] = str(RESOURCE_ROOT / "ML")
RESULTS_FILE = RUNTIME_DIR / "results.json"
STATE_FILE = RUNTIME_DIR / "runtime_state.json"
EXPORT_FILE = RUNTIME_DIR / "export_results.csv"
PCAP_TEST_DIR = BASE_DIR / "ExternalTools" / "tcpreplay-test-kit" / "pcaps"
FAST_PCAP_ANALYSIS_LIMIT = 20000
PCAP_REPLAY_VERSION = 3
MAX_RESULTS = 500
MAX_ALERTS = 250
MAX_HEAL_HISTORY = 100
CAPTURE_PACKET_BATCH = 60
CAPTURE_TIMEOUT_SECONDS = 3
BPF_FILTER = "ip and not (dst host 255.255.255.255 or dst net 224.0.0.0/4)"
RISK_RANK = {"normal": 0, "low": 1, "medium": 2, "high": 3}
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379}
DNS_PORTS = {53, 5353}
INFRA_UDP_PORTS = {53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 1900, 5353}

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from attack_simulator import available_attack_types, simulate_attack
from ips_actions import block_ip as firewall_block_ip
from ips_actions import normalize_ip, unblock_ip as firewall_unblock_ip

app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024


def install_pickle_compat_aliases() -> None:
    try:
        import numpy.core as numpy_core

        sys.modules.setdefault("numpy._core", numpy_core)
    except Exception as exc:
        print(f"Warning: NumPy pickle compatibility aliases unavailable: {exc}")
        return

    for module_name in (
        "_multiarray_umath",
        "multiarray",
        "numeric",
        "numerictypes",
        "umath",
    ):
        try:
            module = __import__(f"numpy.core.{module_name}", fromlist=[module_name])
            sys.modules.setdefault(f"numpy._core.{module_name}", module)
        except Exception:
            continue


def load_models_bundle():
    sys.path.insert(0, str(BASE_DIR))
    install_pickle_compat_aliases()
    try:
        from ML.model_defs import Autoencoder
        import __main__

        __main__.Autoencoder = Autoencoder
    except Exception as exc:
        print(f"Warning: Autoencoder bootstrap failed: {exc}")

    try:
        from ML.predict import load_models, predict_all

        print("Loading ML models...")
        models = load_models()
        print("ML models loaded.")
        return models, predict_all, None
    except Exception as exc:
        print(f"Warning: ML models unavailable: {exc}")
        return None, None, str(exc)


MODELS, PREDICT_ALL, MODEL_LOAD_ERROR = load_models_bundle()


class RuntimeState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.capturing = False
        self.capture_thread: threading.Thread | None = None
        self.selected_iface = ""
        self.capture_error = ""
        self.results: deque[dict] = deque(maxlen=MAX_RESULTS)
        self.alerts: deque[dict] = deque(maxlen=MAX_ALERTS)
        self.blocked_ips: dict[str, dict] = {}
        self.prevention_enabled = False
        self.auto_block_threshold = "high"
        self.healing_enabled = True
        self.healing_window_seconds = 180
        self.healed_events: deque[dict] = deque(maxlen=MAX_HEAL_HISTORY)
        self.attack_runs: deque[dict] = deque(maxlen=50)
        self.failed_ifaces: set[str] = set()
        self.recent_alerts: dict[tuple, float] = {}
        self.packet_debug: deque[dict] = deque(maxlen=80)
        self.capture_stats: Counter = Counter()


STATE = RuntimeState()


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def capture_runtime_state() -> tuple[bool, bool]:
    with STATE.lock:
        thread = STATE.capture_thread
        thread_alive = bool(thread and thread.is_alive())
        if STATE.capturing and not thread_alive:
            STATE.capturing = False
            STATE.capture_thread = None
            if not STATE.capture_error:
                STATE.capture_error = "Capture worker stopped. Ready to start again."
        return STATE.capturing, thread_alive


def to_json_safe(value):
    if isinstance(value, dict):
        return {str(k): to_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, deque)):
        return [to_json_safe(v) for v in value]
    if isinstance(value, np.generic):
        return value.item()
    if isinstance(value, np.ndarray):
        return value.tolist()
    return value


def now_ts() -> float:
    return time.time()


def iso_from_ts(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, UTC).isoformat().replace("+00:00", "Z")


def parse_iso_ts(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def flow_key_tuple(record: dict) -> tuple[str, str, int, int, int]:
    flow_key = record.get("flow_key", {}) if isinstance(record.get("flow_key"), dict) else {}
    return (
        str(flow_key.get("src_ip", "") or ""),
        str(flow_key.get("dst_ip", "") or ""),
        int(flow_key.get("sport", 0) or 0),
        int(flow_key.get("dport", 0) or 0),
        int(flow_key.get("proto", 0) or 0),
    )


def is_duplicate_result(candidate: dict, existing: dict, within_seconds: float = 6.0) -> bool:
    if flow_key_tuple(candidate) != flow_key_tuple(existing):
        return False
    if str(candidate.get("rf_labels", "") or "").upper() != str(existing.get("rf_labels", "") or "").upper():
        return False
    if str(candidate.get("severity", "") or "").lower() != str(existing.get("severity", "") or "").lower():
        return False

    candidate_ts = parse_iso_ts(candidate.get("timestamp"))
    existing_ts = parse_iso_ts(existing.get("timestamp"))
    if candidate_ts is None or existing_ts is None:
        return False
    return abs(candidate_ts - existing_ts) <= within_seconds


def append_results(records: list[dict]) -> int:
    stored = 0
    with STATE.lock:
        existing = list(STATE.results)[:120]
        for record in records:
            if any(is_duplicate_result(record, item) for item in existing):
                continue
            STATE.results.appendleft(record)
            existing.insert(0, record)
            stored += 1
    return stored


def is_suspicious_label(label: str | None) -> bool:
    normalized = str(label or "").upper()
    return normalized not in ("", "BENIGN", "ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "MODELS_UNAVAILABLE", "ERROR")


def threat_heuristics_only(heuristics) -> list[str]:
    benign_markers = {"benign_dns_like", "benign_industrial_polling", "benign_web_like", "rf_benign_override", "public_quic_like", "benign_local_icmp"}
    return [h for h in (heuristics or []) if h not in benign_markers]


def replay_pair_key(record: dict) -> tuple:
    flow_key = (record.get("flow_key", {}) or {}) if isinstance(record.get("flow_key"), dict) else {}
    src_ip = str(flow_key.get("src_ip", "") or "")
    dst_ip = str(flow_key.get("dst_ip", "") or "")
    sport = int(flow_key.get("sport", 0) or 0)
    dport = int(flow_key.get("dport", 0) or 0)
    proto = int(flow_key.get("proto", 0) or 0)
    host_pair = tuple(sorted((src_ip, dst_ip)))
    ephemeral_floor = 49152
    if proto in (1, 58):
        service_port = 0
    elif sport >= ephemeral_floor and dport < ephemeral_floor:
        service_port = dport
    elif dport >= ephemeral_floor and sport < ephemeral_floor:
        service_port = sport
    elif sport and dport:
        service_port = min(sport, dport)
    else:
        service_port = max(sport, dport)
    return (proto, host_pair, service_port)


def is_privateish_ip(value: str) -> bool:
    try:
        parsed = ip_address(str(value or "").split("%")[0])
        return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved)
    except Exception:
        return False


def is_public_ip(value: str) -> bool:
    try:
        parsed = ip_address(str(value or "").split("%")[0])
        return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved or parsed.is_multicast or parsed.is_unspecified)
    except Exception:
        return False


def looks_like_public_quic(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 17:
        return False

    src_ip = str(flow_info.get("src_ip", "") or "")
    dst_ip = str(flow_info.get("dst_ip", "") or "")
    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
    flow_pps = float(flow_info.get("flow_packets/s", 0) or 0)

    has_public_peer = (is_privateish_ip(src_ip) and is_public_ip(dst_ip)) or (is_public_ip(src_ip) and is_privateish_ip(dst_ip))
    if not has_public_peer:
        return False

    if 443 not in (sport, dport):
        return False

    return total_pkts <= 180 and avg_pkt_size < 1100 and flow_pps < 1200


def raise_risk(current: str | None, target: str) -> str:
    current_norm = str(current or "normal").lower()
    target_norm = str(target or "normal").lower()
    return target_norm if RISK_RANK.get(target_norm, 0) > RISK_RANK.get(current_norm, 0) else current_norm


def looks_like_benign_dns(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 17:
        return False
    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
    flow_pps = float(flow_info.get("flow_packets/s", 0) or 0)
    return (sport in DNS_PORTS or dport in DNS_PORTS) and total_pkts <= 40 and avg_pkt_size <= 350 and flow_pps <= 120


def looks_like_service_probe(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 6:
        return False
    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    syn_count = int(flow_info.get("syn_flag_count", 0) or 0)
    ack_count = int(flow_info.get("ack_flag_count", 0) or 0)
    rst_count = int(flow_info.get("rst_flag_count", 0) or 0)
    return syn_count >= 1 and total_pkts <= 8 and (ack_count <= 2 or rst_count >= 1)


def looks_like_benign_industrial_polling(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 6:
        return False

    src_ip = str(flow_info.get("src_ip", "") or "")
    dst_ip = str(flow_info.get("dst_ip", "") or "")
    if not (is_privateish_ip(src_ip) and is_privateish_ip(dst_ip)):
        return False

    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    industrial_ports = {102, 502, 2404, 20000, 44818, 47808, 1911, 9600, 5440}
    if sport not in industrial_ports and dport not in industrial_ports:
        return False

    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    bwd_pkts = int(flow_info.get("total_backward_packets", 0) or 0)
    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
    syn_count = int(flow_info.get("syn_flag_count", 0) or 0)
    rst_count = int(flow_info.get("rst_flag_count", 0) or 0)
    ack_count = int(flow_info.get("ack_flag_count", 0) or 0)

    return total_pkts >= 3 and total_pkts <= 40 and bwd_pkts >= 1 and avg_pkt_size <= 200 and syn_count <= 2 and rst_count <= 2 and ack_count >= 1


def looks_like_benign_local_icmp(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 1:
        return False

    src_ip = str(flow_info.get("src_ip", "") or "")
    dst_ip = str(flow_info.get("dst_ip", "") or "")
    if not (is_privateish_ip(src_ip) and is_privateish_ip(dst_ip)):
        return False

    fwd_pkts = int(flow_info.get("total_fwd_packets", 0) or 0)
    bwd_pkts = int(flow_info.get("total_backward_packets", 0) or 0)
    total_pkts = fwd_pkts + bwd_pkts
    if total_pkts < 4 or min(fwd_pkts, bwd_pkts) < 2:
        return False

    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
    flow_pps = float(flow_info.get("flow_packets/s", 0) or 0)
    flow_bps = float(flow_info.get("flow_bytes/s", 0) or 0)
    balance = min(fwd_pkts, bwd_pkts) / max(fwd_pkts, bwd_pkts, 1)

    if avg_pkt_size > 256:
        return False
    if flow_pps > 30 or flow_bps > 50000:
        return False

    return balance >= 0.55


def looks_like_benign_web_session(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 6:
        return False

    src_ip = str(flow_info.get("src_ip", "") or "")
    dst_ip = str(flow_info.get("dst_ip", "") or "")
    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    web_ports = {80, 443, 8080, 8443}
    if sport not in web_ports and dport not in web_ports:
        return False

    has_public_peer = (is_privateish_ip(src_ip) and is_public_ip(dst_ip)) or (is_public_ip(src_ip) and is_privateish_ip(dst_ip))
    if not has_public_peer:
        return False

    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    bwd_pkts = int(flow_info.get("total_backward_packets", 0) or 0)
    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
    syn_count = int(flow_info.get("syn_flag_count", 0) or 0)
    rst_count = int(flow_info.get("rst_flag_count", 0) or 0)

    return total_pkts >= 6 and total_pkts <= 500 and bwd_pkts >= 2 and avg_pkt_size <= 1600 and syn_count <= 3 and rst_count <= 2


def looks_like_packet_injection(flow_info: dict) -> bool:
    proto = int(flow_info.get("proto", 0) or 0)
    if proto != 6:
        return False

    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    if 80 not in (sport, dport):
        return False

    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    if total_pkts < 4:
        return False

    fwd_seq_dup = int(flow_info.get("fwd_tcp_seq_dup_count", 0) or 0)
    fwd_ack_dup = int(flow_info.get("fwd_tcp_ack_dup_count", 0) or 0)
    bwd_ttl_unique = int(flow_info.get("bwd_ttl_unique_count", 0) or 0)
    bwd_seq_dup = int(flow_info.get("bwd_tcp_seq_dup_count", 0) or 0)
    bwd_ack_dup = int(flow_info.get("bwd_tcp_ack_dup_count", 0) or 0)
    bwd_synack_dup = int(flow_info.get("bwd_synack_count", 0) or 0)
    bwd_http_status_count = int(flow_info.get("bwd_http_status_count", 0) or 0)
    total_bwd_pkts = int(flow_info.get("total_backward_packets", 0) or 0)
    rst_count = int(flow_info.get("rst_flag_count", 0) or 0)
    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)

    strong_http_conflict = bwd_ttl_unique >= 2 and bwd_http_status_count >= 2 and total_pkts <= 20
    synack_collision = bwd_ttl_unique >= 2 and bwd_synack_dup >= 2
    heavy_response_collision = bwd_ttl_unique >= 2 and (
        (bwd_seq_dup >= 5 and bwd_ack_dup >= 40 and fwd_seq_dup >= 20)
        or (bwd_seq_dup >= 8 and bwd_ack_dup >= 20 and total_bwd_pkts >= 40)
    )
    short_response_collision = (
        bwd_ttl_unique >= 2
        and bwd_seq_dup >= 2
        and fwd_seq_dup >= 2
        and fwd_ack_dup >= 2
        and total_bwd_pkts <= 12
        and (bwd_http_status_count >= 1 or bwd_synack_dup >= 2)
    )
    reset_collision = rst_count >= 2 and bwd_ttl_unique >= 2 and bwd_seq_dup >= 1
    ttl_burst_collision = bwd_ttl_unique >= 3 and (bwd_http_status_count >= 2 or bwd_synack_dup >= 2)

    return avg_pkt_size >= 40 and (
        strong_http_conflict
        or synack_collision
        or heavy_response_collision
        or short_response_collision
        or reset_collision
        or ttl_burst_collision
    )


def compute_heal_at(blocked_at: str | None, window_seconds: int) -> str:
    blocked_ts = parse_iso_ts(blocked_at)
    if blocked_ts is None:
        blocked_ts = now_ts()
    return iso_from_ts(blocked_ts + max(30, int(window_seconds)))


def normalize_block_entry(ip: str, metadata: dict) -> dict:
    entry = dict(metadata or {})
    source = str(entry.get("block_source", "") or "").lower()
    if not source:
        source = "auto" if str(entry.get("reason", "") or "").startswith("Auto-blocked") else "manual"
    entry["block_source"] = source
    entry["ip"] = ip
    entry["status"] = entry.get("status") or ("active" if entry.get("applied") else "pending")
    entry["blocked_at"] = entry.get("blocked_at") or now_iso()
    if source == "auto":
        entry["heal_at"] = entry.get("heal_at") or compute_heal_at(entry.get("blocked_at"), STATE.healing_window_seconds)
        entry["heal_status"] = entry.get("heal_status") or "scheduled"
    return entry


def persist_results() -> None:
    with STATE.lock:
        RESULTS_FILE.write_text(json.dumps(to_json_safe(list(STATE.results)), indent=2), encoding="utf-8")
        STATE_FILE.write_text(
            json.dumps(
                to_json_safe(
                    {
                        "blocked_ips": STATE.blocked_ips,
                        "prevention_enabled": STATE.prevention_enabled,
                        "auto_block_threshold": STATE.auto_block_threshold,
                        "healing_enabled": STATE.healing_enabled,
                        "healing_window_seconds": STATE.healing_window_seconds,
                        "healed_events": list(STATE.healed_events),
                        "selected_iface": STATE.selected_iface,
                    }
                ),
                indent=2,
            ),
            encoding="utf-8",
        )


def load_persisted_state() -> None:
    with STATE.lock:
        if RESULTS_FILE.exists():
            try:
                raw_results = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
                if isinstance(raw_results, list):
                    filtered_results = []
                    for row in raw_results[:MAX_RESULTS]:
                        if not isinstance(row, dict):
                            continue
                        text_blob = json.dumps(row)
                        if any(marker in text_blob for marker in ("SELF-TEST", "local lab test", "attack_test_confirmed", "attack_test_match", "icmp_self_test")):
                            continue
                        if str(row.get("rf_labels", "") or "").upper() in {"MODELS_UNAVAILABLE", "ERROR"}:
                            continue
                        filtered_results.append(row)
                    STATE.results = deque(filtered_results, maxlen=MAX_RESULTS)
            except Exception as exc:
                print(f"Warning: Failed to load persisted results: {exc}")

        if STATE_FILE.exists():
            try:
                raw_state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                if isinstance(raw_state, dict):
                    blocked_ips = raw_state.get("blocked_ips", {})
                    if isinstance(blocked_ips, dict):
                        STATE.blocked_ips = {ip: normalize_block_entry(ip, metadata) for ip, metadata in blocked_ips.items() if isinstance(metadata, dict)}
                    prevention_enabled = raw_state.get("prevention_enabled")
                    if isinstance(prevention_enabled, bool):
                        STATE.prevention_enabled = prevention_enabled
                    threshold = str(raw_state.get("auto_block_threshold", STATE.auto_block_threshold)).lower()
                    if threshold in RISK_RANK:
                        STATE.auto_block_threshold = threshold
                    healing_enabled = raw_state.get("healing_enabled")
                    if isinstance(healing_enabled, bool):
                        STATE.healing_enabled = healing_enabled
                    healing_window_seconds = raw_state.get("healing_window_seconds")
                    if isinstance(healing_window_seconds, (int, float)):
                        STATE.healing_window_seconds = max(30, int(healing_window_seconds))
                    healed_events = raw_state.get("healed_events", [])
                    if isinstance(healed_events, list):
                        STATE.healed_events = deque(healed_events[:MAX_HEAL_HISTORY], maxlen=MAX_HEAL_HISTORY)
                    selected_iface = raw_state.get("selected_iface")
                    if isinstance(selected_iface, str):
                        STATE.selected_iface = selected_iface
                    if STATE.blocked_ips:
                        STATE.blocked_ips = {ip: normalize_block_entry(ip, metadata) for ip, metadata in STATE.blocked_ips.items()}
            except Exception as exc:
                print(f"Warning: Failed to load persisted runtime state: {exc}")


def packet_summary(pkt, iface_name: str | None = None) -> dict:
    proto = None
    src_ip = ""
    dst_ip = ""
    sport = 0
    dport = 0
    if IP in pkt:
        proto = int(pkt[IP].proto)
        src_ip = str(pkt[IP].src)
        dst_ip = str(pkt[IP].dst)
    if TCP in pkt or UDP in pkt:
        sport = int(getattr(pkt, "sport", 0) or 0)
        dport = int(getattr(pkt, "dport", 0) or 0)
    return {
        "timestamp": now_iso(),
        "iface": iface_name or "",
        "proto": proto,
        "proto_name": PROTO_NAMES.get(proto, str(proto)),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "sport": sport,
        "dport": dport,
        "length": int(len(pkt)),
    }


def record_packet_debug(packets, iface_name: str | None = None) -> None:
    entries = [packet_summary(pkt, iface_name) for pkt in packets if IP in pkt]
    if not entries:
        return
    with STATE.lock:
        for entry in entries:
            STATE.packet_debug.appendleft(entry)
            STATE.capture_stats["packets_total"] += 1
            STATE.capture_stats[f"proto_{entry['proto_name']}"] += 1


def windows_capture_iface_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    if os.name != "nt":
        return mapping

    try:
        from scapy.arch.windows import get_windows_if_list

        for iface in get_windows_if_list():
            friendly_name = str(iface.get("name", "") or "").strip()
            description = str(iface.get("description", "") or "").strip()
            guid = str(iface.get("guid", "") or "").strip()

            if not friendly_name:
                continue

            capture_name = friendly_name

            for key in (friendly_name, description, guid, capture_name):
                if key:
                    mapping[key] = capture_name
    except Exception:
        pass

    return mapping


def resolve_capture_iface(iface_name: str) -> str:
    if not iface_name:
        return iface_name
    if os.name == "nt":
        loopback_names = {
            "loopback pseudo-interface 1",
            r"\device\npf_loopback",
        }
        if iface_name.strip().lower() in loopback_names:
            return "Loopback Pseudo-Interface 1"
    return windows_capture_iface_map().get(iface_name, iface_name)


load_persisted_state()


def is_loopback_iface(iface_name: str) -> bool:
    lowered = str(iface_name or "").strip().lower()
    return "loopback" in lowered or lowered in {"lo", "lo0"}


def get_interfaces() -> list[str]:
    interfaces = set()
    stats = psutil.net_if_stats()
    for name in psutil.net_if_addrs().keys():
        if name in stats and not stats[name].isup:
            continue
        interfaces.add(name)
    try:
        from scapy.config import conf

        if getattr(conf, "ifaces", None):
            for iface in conf.ifaces.values():
                iface_name = getattr(iface, "name", None)
                if not iface_name:
                    continue
                interfaces.add(iface_name)
    except Exception:
        pass
    ordered = sorted(iface for iface in interfaces if iface)
    preferred = []
    others = []
    for iface in ordered:
        lowered = iface.lower()
        if is_loopback_iface(iface):
            continue
        if lowered in {"wi-fi", "wifi", "wlan", "ethernet"}:
            preferred.append(iface)
        else:
            others.append(iface)
    loopbacks = [iface for iface in ordered if is_loopback_iface(iface)]
    return preferred + others + loopbacks


def interface_inventory() -> list[dict]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    inventory: list[dict] = []
    seen: set[str] = set()

    ordered_names = get_interfaces() + [name for name in addrs.keys() if name not in get_interfaces()]
    for name in ordered_names:
        if not name or name in seen:
            continue
        seen.add(name)

        ipv4: list[str] = []
        ipv6: list[str] = []
        for addr in addrs.get(name, []):
            family_name = getattr(addr.family, "name", str(addr.family))
            address = str(getattr(addr, "address", "") or "")
            if not address:
                continue
            if family_name == "AF_INET":
                ipv4.append(address)
            elif family_name == "AF_INET6":
                ipv6.append(address.split("%")[0])

        primary_ipv4 = ""
        for candidate in ipv4:
            if not candidate.startswith("169.254."):
                primary_ipv4 = candidate
                break
        if not primary_ipv4 and ipv4:
            primary_ipv4 = ipv4[0]

        inventory.append(
            {
                "name": name,
                "is_up": bool(stats.get(name).isup) if name in stats else True,
                "is_loopback": is_loopback_iface(name),
                "ipv4": ipv4,
                "ipv6": ipv6,
                "primary_ipv4": primary_ipv4,
            }
        )

    return inventory


def interface_primary_ipv4(iface_name: str) -> str:
    requested = str(iface_name or "").strip().lower()
    if not requested:
        return ""

    for item in interface_inventory():
        name = str(item.get("name", "")).strip().lower()
        if name == requested:
            return str(item.get("primary_ipv4", "") or "")

    resolved = str(resolve_capture_iface(iface_name) or "").strip().lower()
    if resolved and resolved != requested:
        for item in interface_inventory():
            name = str(item.get("name", "")).strip().lower()
            if name == resolved:
                return str(item.get("primary_ipv4", "") or "")

    return ""


def preferred_attack_target(iface_name: str = "") -> tuple[str, str]:
    candidates = [iface_name, STATE.selected_iface]
    for candidate in candidates:
        ip = interface_primary_ipv4(candidate)
        if ip:
            return ip, candidate

    for item in interface_inventory():
        if item.get("is_loopback"):
            continue
        if item.get("primary_ipv4"):
            return str(item["primary_ipv4"]), str(item["name"])

    return "127.0.0.1", "Loopback"


def pcap_is_readable(path: Path) -> bool:
    try:
        with PcapReader(str(path)) as reader:
            for _ in reader:
                return True
    except Exception:
        return False
    return False


def available_pcap_files() -> list[dict]:
    if not PCAP_TEST_DIR.exists():
        return []

    pcaps = []
    for path in sorted(PCAP_TEST_DIR.glob("*.pcap")):
        if not pcap_is_readable(path):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        pcaps.append(
            {
                "name": path.name,
                "path": str(path),
                "size_bytes": int(size),
                **pcap_profile_info(path.name),
            }
        )
    return pcaps


def pcap_profile_info(pcap_name: str) -> dict:
    name = str(pcap_name or "").strip().lower()
    if name.startswith("attack-") or "packet-injection" in name:
        return {
            "benchmark_profile": "attack",
            "benchmark_goal": "Elevate malicious web injection pairs",
            "benchmark_score_kind": "attack_coverage",
        }
    if name.startswith("4sics-"):
        return {
            "benchmark_profile": "baseline",
            "benchmark_goal": "Stay quiet on benign ICS baseline traffic",
            "benchmark_score_kind": "baseline_quiet",
        }
    if name == "smallflows.pcap":
        return {
            "benchmark_profile": "baseline",
            "benchmark_goal": "Stay mostly quiet on ordinary traffic",
            "benchmark_score_kind": "baseline_quiet",
        }
    if name == "bigflows.pcap":
        return {
            "benchmark_profile": "mixed",
            "benchmark_goal": "Maintain low noise on mixed traffic while still surfacing strong attack pairs",
            "benchmark_score_kind": "mixed_quiet",
        }
    return {
        "benchmark_profile": "unknown",
        "benchmark_goal": "General replay validation",
        "benchmark_score_kind": "mixed_quiet",
    }


def save_uploaded_pcap(file_storage) -> dict:
    if file_storage is None:
        raise ValueError("No file was uploaded")

    original_name = str(getattr(file_storage, "filename", "") or "").strip()
    if not original_name:
        raise ValueError("Uploaded file is missing a filename")

    safe_name = secure_filename(Path(original_name).name)
    if not safe_name.lower().endswith(".pcap"):
        raise ValueError("Only .pcap files are supported")

    PCAP_TEST_DIR.mkdir(parents=True, exist_ok=True)
    destination = PCAP_TEST_DIR / safe_name
    file_storage.save(destination)
    size = destination.stat().st_size if destination.exists() else 0
    return {
        "name": safe_name,
        "path": str(destination),
        "size_bytes": int(size),
    }


def load_pcap_packets(pcap_path: Path, packet_limit: int | None = None) -> list:
    if PcapReader is None:
        packets = list(rdpcap(str(pcap_path)))
        if packet_limit is not None and int(packet_limit) > 0:
            return packets[: int(packet_limit)]
        return packets

    packets = []
    limit = int(packet_limit) if packet_limit is not None and int(packet_limit) > 0 else None
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            packets.append(packet)
            if limit is not None and len(packets) >= limit:
                break
    return packets


def replay_pcap_file(
    pcap_name: str,
    iface: str | None = None,
    packet_limit: int | None = None,
    loop_count: int = 1,
    packets_per_second: float | None = None,
) -> dict:
    if rdpcap is None or send is None or sendp is None:
        raise RuntimeError("Scapy replay support is not installed.")

    requested = str(pcap_name or "").strip()
    if not requested:
        raise ValueError("pcap_name is required")

    safe_name = Path(requested).name
    pcap_path = PCAP_TEST_DIR / safe_name
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {safe_name}")

    packets = load_pcap_packets(pcap_path, packet_limit=packet_limit)
    if not packets:
        raise ValueError(f"PCAP is empty: {safe_name}")

    loop_count = max(1, int(loop_count or 1))
    replay_packets = []
    for _ in range(loop_count):
        replay_packets.extend(packet.copy() for packet in packets)

    pps = float(packets_per_second or 0)
    inter = (1.0 / pps) if pps > 0 else 0.01
    started = time.time()
    for idx, packet in enumerate(replay_packets):
        packet.time = started + (idx * inter)

    send_kwargs = {"verbose": False}
    resolved_iface = resolve_capture_iface(iface or "")
    if resolved_iface:
        send_kwargs["iface"] = resolved_iface

    if any(packet.haslayer(Ether) for packet in replay_packets if Ether is not None):
        sendp(replay_packets, inter=inter, **send_kwargs)
    else:
        send(replay_packets, inter=inter, **send_kwargs)

    duration = round(time.time() - started, 3)
    return {
        "pcap_name": safe_name,
        "pcap_path": str(pcap_path),
        "iface": iface,
        "resolved_iface": resolved_iface,
        "packet_count": len(replay_packets),
        "loop_count": loop_count,
        "packets_per_second": pps or None,
        "duration_seconds": duration,
        "_packets": replay_packets,
    }


def send_replay_packets_in_batches(
    replay_packets: list,
    iface: str | None = None,
    packets_per_second: float | None = None,
    progress_callback=None,
) -> dict:
    if send is None or sendp is None:
        raise RuntimeError("Scapy replay support is not installed.")

    total_packets = len(replay_packets)
    if total_packets <= 0:
        return {"resolved_iface": resolve_capture_iface(iface or ""), "duration_seconds": 0.0}

    pps = float(packets_per_second or 0)
    inter = (1.0 / pps) if pps > 0 else 0.001
    if os.name == "nt":
        if total_packets >= 20000:
            batch_size = 256
        elif total_packets >= 5000:
            batch_size = 128
        elif total_packets >= 1000:
            batch_size = 64
        else:
            batch_size = 16
    else:
        batch_size = 512 if total_packets > 2048 else (256 if total_packets > 512 else max(1, total_packets))
    send_kwargs = {"verbose": False}
    resolved_iface = resolve_capture_iface(iface or "")
    if resolved_iface:
        send_kwargs["iface"] = resolved_iface

    uses_l2 = any(packet.haslayer(Ether) for packet in replay_packets if Ether is not None)
    sender = sendp if uses_l2 else send
    started = time.time()

    for offset in range(0, total_packets, batch_size):
        batch = replay_packets[offset:offset + batch_size]
        batch_inter = inter if len(batch) <= 8 else min(inter, 0.0002) if pps > 0 else 0
        sender(batch, inter=batch_inter, **send_kwargs)
        if progress_callback:
            progress_callback(min(total_packets, offset + len(batch)), total_packets)
        if os.name == "nt" and total_packets > 1000:
            time.sleep(0.001)

    return {
        "resolved_iface": resolved_iface,
        "duration_seconds": round(time.time() - started, 3),
    }


def update_attack_run(run_id: str, **updates) -> None:
    with STATE.lock:
        for run in STATE.attack_runs:
            if run.get("id") == run_id:
                run.update(updates)
                break


def process_pcap_replay_async(
    replay_id: str,
    pcap_name: str,
    requested_iface: str | None,
    packet_limit: int | None,
    loop_count: int,
    packets_per_second: float | None,
    send_packets: bool,
    started_ts: float,
) -> None:
    try:
        effective_packet_limit = packet_limit
        auto_limited = False
        if not send_packets and (effective_packet_limit is None or int(effective_packet_limit) <= 0):
            effective_packet_limit = FAST_PCAP_ANALYSIS_LIMIT
            auto_limited = True

        update_attack_run(
            replay_id,
            replay_status="running",
            replay_phase="loading",
            replay_progress_pct=2.0,
            packet_limit=effective_packet_limit,
            auto_limited=auto_limited,
        )
        replay = replay_pcap_file(
            pcap_name=pcap_name,
            iface=requested_iface or STATE.selected_iface,
            packet_limit=effective_packet_limit,
            loop_count=loop_count,
            packets_per_second=packets_per_second,
        )
        replay_packets = list(replay.pop("_packets", []) or [])
        if replay_packets:
            update_attack_run(
                replay_id,
                packet_count=int(replay.get("packet_count") or len(replay_packets)),
                replay_phase="extracting_features",
                replay_progress_pct=15.0,
            )
            replay_rows = feature_rows_from_packets(replay_packets)
            update_attack_run(
                replay_id,
                total_flow_count=len(replay_rows),
                matched_flows=len(replay_rows),
                replay_phase="scoring",
                replay_progress_pct=55.0,
            )
            replay_records = score_rows(replay_rows)
            suspicious_flow_count = 0
            suspicious_detected_flows = 0
            elevated_detected_flows = 0
            total_pairs = set()
            suspicious_pairs = set()
            elevated_pairs = set()
            first_label = None
            suspicious_label_counter = Counter()
            for record in replay_records:
                record["attack_run_id"] = replay_id
                record["attack_run_label"] = "PCAP Replay"
                record["traffic_source"] = "pcap_replay"
                pair_key = replay_pair_key(record)
                total_pairs.add(pair_key)
                threat_heuristics = threat_heuristics_only(record.get("heuristics"))
                is_suspicious_flow = (
                    is_suspicious_label(record.get("rf_labels"))
                    or str(record.get("severity", "normal")).lower() in ("medium", "high")
                    or bool(record.get("ae_anomaly"))
                    or bool(threat_heuristics)
                )
                if is_suspicious_flow:
                    suspicious_flow_count += 1
                    suspicious_detected_flows += 1
                    suspicious_pairs.add(pair_key)
                    suspicious_label_counter[str(record.get("rf_labels") or "UNKNOWN")] += 1
                    if first_label is None:
                        first_label = record.get("rf_labels")
                if str(record.get("severity", "normal")).lower() in ("medium", "high"):
                    elevated_detected_flows += 1
                    elevated_pairs.add(pair_key)
                    if first_label is None:
                        first_label = record.get("rf_labels")
            total_pair_count = len(total_pairs)
            suspicious_pair_count = len(suspicious_pairs)
            elevated_pair_count = len(elevated_pairs)
            profile_info = pcap_profile_info(pcap_name)
            benchmark_profile = str(profile_info.get("benchmark_profile", "unknown") or "unknown")
            benchmark_kind = str(profile_info.get("benchmark_score_kind", "mixed_quiet") or "mixed_quiet")
            if benchmark_kind == "attack_coverage":
                benchmark_score_pct = round((elevated_pair_count / total_pair_count) * 100, 2) if total_pair_count else 0.0
                benchmark_score_label = "Attack coverage"
            elif benchmark_kind == "baseline_quiet":
                benchmark_score_pct = round(100.0 - ((elevated_pair_count / total_pair_count) * 100), 2) if total_pair_count else 100.0
                benchmark_score_label = "Quiet baseline"
            else:
                benchmark_score_pct = round(100.0 - ((elevated_pair_count / total_pair_count) * 100), 2) if total_pair_count else 100.0
                benchmark_score_label = "Noise control"
            append_results(replay_records)
            update_attack_run(
                replay_id,
                matched_flows=len(replay_records),
                total_flow_count=len(replay_records),
                total_pair_count=total_pair_count,
                attack_candidate_flows=suspicious_flow_count,
                detection_count=suspicious_detected_flows,
                elevated_detection_count=elevated_detected_flows,
                suspicious_pair_count=suspicious_pair_count,
                elevated_pair_count=elevated_pair_count,
                first_detected_label=first_label,
                top_detected_labels=[{"label": label, "count": count} for label, count in suspicious_label_counter.most_common(5)],
                replay_phase="finalizing",
                replay_progress_pct=85.0 if send_packets else 95.0,
                detection_rate_pct=round((suspicious_detected_flows / suspicious_flow_count) * 100, 2) if suspicious_flow_count else 0.0,
                elevated_detection_rate_pct=round((elevated_detected_flows / suspicious_flow_count) * 100, 2) if suspicious_flow_count else 0.0,
                elevated_pair_rate_pct=round((elevated_pair_count / suspicious_pair_count) * 100, 2) if suspicious_pair_count else 0.0,
                total_pair_elevated_rate_pct=round((elevated_pair_count / total_pair_count) * 100, 2) if total_pair_count else 0.0,
                suspicious_pair_rate_pct=round((suspicious_pair_count / total_pair_count) * 100, 2) if total_pair_count else 0.0,
                benchmark_profile=benchmark_profile,
                benchmark_score_kind=benchmark_kind,
                benchmark_score_pct=benchmark_score_pct,
                benchmark_score_label=benchmark_score_label,
            )
            if send_packets:
                send_result = send_replay_packets_in_batches(
                    replay_packets,
                    iface=requested_iface or STATE.selected_iface,
                    packets_per_second=packets_per_second,
                    progress_callback=lambda sent_count, total_count: update_attack_run(
                        replay_id,
                        replay_status="running",
                        replay_phase="sending_packets",
                        sent_packet_count=sent_count,
                        replay_progress_pct=round(85.0 + ((sent_count / max(1, total_count)) * 14.0), 1),
                    ),
                )
            else:
                send_result = {
                    "resolved_iface": resolve_capture_iface(requested_iface or STATE.selected_iface),
                    "duration_seconds": 0.0,
                }
            update_attack_run(
                replay_id,
                replay_status="completed",
                replay_error=None,
                finished_ts=started_ts + float(send_result.get("duration_seconds") or replay.get("duration_seconds") or 0),
                packet_count=int(replay.get("packet_count") or 0),
                sent_packet_count=int(replay.get("packet_count") or 0) if send_packets else 0,
                matched_flows=len(replay_records),
                total_flow_count=len(replay_records),
                total_pair_count=total_pair_count,
                attack_candidate_flows=suspicious_flow_count,
                detection_count=suspicious_detected_flows,
                elevated_detection_count=elevated_detected_flows,
                suspicious_pair_count=suspicious_pair_count,
                elevated_pair_count=elevated_pair_count,
                first_detected_label=first_label,
                top_detected_labels=[{"label": label, "count": count} for label, count in suspicious_label_counter.most_common(5)],
                replay_progress_pct=100.0,
                replay_phase="completed",
                resolved_iface=send_result.get("resolved_iface"),
                replay_mode="wire" if send_packets else "analysis_only",
                detection_rate_pct=round((suspicious_detected_flows / suspicious_flow_count) * 100, 2) if suspicious_flow_count else 0.0,
                elevated_detection_rate_pct=round((elevated_detected_flows / suspicious_flow_count) * 100, 2) if suspicious_flow_count else 0.0,
                elevated_pair_rate_pct=round((elevated_pair_count / suspicious_pair_count) * 100, 2) if suspicious_pair_count else 0.0,
                total_pair_elevated_rate_pct=round((elevated_pair_count / total_pair_count) * 100, 2) if total_pair_count else 0.0,
                suspicious_pair_rate_pct=round((suspicious_pair_count / total_pair_count) * 100, 2) if total_pair_count else 0.0,
            )
        else:
            update_attack_run(
                replay_id,
                replay_status="completed",
                replay_error=None,
                finished_ts=started_ts,
                packet_count=0,
                sent_packet_count=0,
                matched_flows=0,
                total_flow_count=0,
                total_pair_count=0,
                attack_candidate_flows=0,
                detection_count=0,
                elevated_detection_count=0,
                suspicious_pair_count=0,
                elevated_pair_count=0,
                top_detected_labels=[],
                replay_progress_pct=100.0,
                replay_phase="completed",
                replay_mode="wire" if send_packets else "analysis_only",
                detection_rate_pct=0.0,
                elevated_detection_rate_pct=0.0,
                elevated_pair_rate_pct=0.0,
                total_pair_elevated_rate_pct=0.0,
                suspicious_pair_rate_pct=0.0,
            )
        persist_results()
    except Exception as exc:
        update_attack_run(
            replay_id,
            replay_status="failed",
            replay_error=str(exc),
            finished_ts=now_ts(),
            replay_phase="failed",
        )
        persist_results()


def build_capture_ifaces(primary_iface: str) -> list[str]:
    resolved_primary = resolve_capture_iface(primary_iface)
    if os.name == "nt":
        final_ifaces: list[str] = []
        seen: set[str] = set()

        def add_iface(iface_name: str) -> None:
            resolved = resolve_capture_iface(iface_name)
            if not resolved or resolved in seen or resolved in STATE.failed_ifaces:
                return
            seen.add(resolved)
            final_ifaces.append(resolved)

        if resolved_primary and not is_loopback_iface(resolved_primary):
            add_iface(resolved_primary)

        for item in interface_inventory():
            if not item.get("is_up"):
                continue
            if item.get("is_loopback"):
                add_iface(str(item.get("name") or ""))

        if final_ifaces:
            return final_ifaces

        available = get_interfaces()
        for iface in available:
            if is_loopback_iface(iface):
                continue
            resolved = resolve_capture_iface(iface)
            if resolved and resolved not in STATE.failed_ifaces:
                add_iface(resolved)
                break

        if final_ifaces:
            return final_ifaces

        return [resolved_primary] if resolved_primary else []

    candidates = [primary_iface]
    stats = psutil.net_if_stats()
    for name in psutil.net_if_addrs().keys():
        if name in stats and not stats[name].isup:
            continue
        candidates.append(name)

    final_ifaces = []
    seen = set()
    for iface in candidates:
        resolved = resolve_capture_iface(iface)
        if resolved and resolved not in seen and resolved not in STATE.failed_ifaces:
            seen.add(resolved)
            final_ifaces.append(resolved)
    return final_ifaces


def capture_packets_with_fallback(ifaces: list[str], packet_count: int, timeout_sec: int):
    if sniff is None:
        raise RuntimeError("Scapy is not installed.")
    if not ifaces:
        return []

    if os.name == "nt":
        merged = []
        per_iface_timeout = max(1, timeout_sec / max(1, len(ifaces)))
        for iface in ifaces:
            try:
                packets = sniff(iface=iface, filter=BPF_FILTER, count=packet_count, timeout=per_iface_timeout)
                record_packet_debug(packets, iface)
                merged.extend(packets)
            except Exception as primary_err:
                with STATE.lock:
                    STATE.failed_ifaces.add(iface)
                print(f"Capture failed on {iface}: {primary_err}")
        return merged

    try:
        iface_arg = ifaces if len(ifaces) > 1 else ifaces[0]
        packets = sniff(iface=iface_arg, filter=BPF_FILTER, count=packet_count, timeout=timeout_sec)
        record_packet_debug(packets, ",".join(ifaces))
        return packets
    except Exception as multi_err:
        print(f"Multi-interface capture fallback triggered: {multi_err}")

    merged = []
    per_iface_count = max(1, packet_count // max(1, len(ifaces)))
    per_iface_timeout = max(1, timeout_sec / max(1, len(ifaces)))
    for iface in ifaces:
        try:
            packets = sniff(iface=iface, filter=BPF_FILTER, count=per_iface_count, timeout=per_iface_timeout)
            record_packet_debug(packets, iface)
            merged.extend(packets)
        except Exception as one_err:
            with STATE.lock:
                STATE.failed_ifaces.add(iface)
            print(f"Capture failed on {iface}: {one_err}")
    return merged


def apply_traffic_heuristics(flow_info: dict, pred: dict) -> tuple[dict, list[str]]:
    heuristics: list[str] = []
    proto = int(flow_info.get("proto", 0) or 0)
    src_ip = str(flow_info.get("src_ip", "") or "")
    dst_ip = str(flow_info.get("dst_ip", "") or "")
    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
    flow_pps = float(flow_info.get("flow_packets/s", 0) or 0)
    flow_bps = float(flow_info.get("flow_bytes/s", 0) or 0)
    total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
    ack_count = int(flow_info.get("ack_flag_count", 0) or 0)
    rst_count = int(flow_info.get("rst_flag_count", 0) or 0)
    rf_probs = pred.get("rf_probs") if isinstance(pred.get("rf_probs"), dict) else {}
    rf_benign_prob = float(rf_probs.get("BENIGN", 0) or 0)

    if proto == 1 and total_pkts >= 4 and flow_pps >= 0.8:
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "low")
        heuristics.append("icmp_repeated")
        if str(pred.get("rf_labels", "BENIGN")).upper() == "BENIGN":
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "ICMP-ANOMALY"

    if proto == 1 and avg_pkt_size >= 900 and (total_pkts >= 2 or flow_pps >= 1.2) and flow_bps >= 2500:
        pred["ae_anomaly"] = True
        pred["iso_risk"] = "high"
        pred["kmeans_risk"] = "medium"
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "high")
        heuristics.append("icmp_large_repeated")
        if str(pred.get("rf_labels", "BENIGN")).upper() == "BENIGN":
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "ICMP-FLOOD"

    if looks_like_benign_local_icmp(flow_info):
        heuristics.append("benign_local_icmp")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("ICMP-ANOMALY", "ICMP-FLOOD", "ANOMALOUS-TRAFFIC"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "BENIGN"
        pred["ae_anomaly"] = False
        pred["iso_risk"] = "normal"
        pred["kmeans_risk"] = "normal"
        pred["ensemble_risk"] = "normal"

    syn_count = int(flow_info.get("syn_flag_count", 0) or 0)
    if proto == 6 and syn_count >= 1 and total_pkts <= 3 and ack_count == 0 and rst_count <= 1:
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "low")
        heuristics.append("tcp_probe")

    if proto == 6 and dport in AUTH_PORTS and looks_like_service_probe(flow_info):
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "medium")
        heuristics.append("auth_probe")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("BENIGN", "PORTSCAN", "ANOMALOUS-TRAFFIC"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "AUTH-PROBE"

    if proto == 6 and rst_count >= 2 and syn_count >= 1 and ack_count <= 1 and total_pkts <= 8:
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "medium")
        heuristics.append("tcp_rst_probe")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("BENIGN", "ANOMALOUS-TRAFFIC"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "RST-SCAN"

    bwd_pkts = int(flow_info.get("total_backward_packets", 0) or 0)
    if proto == 6 and syn_count >= 40 and flow_pps >= 80 and ack_count <= max(2, int(syn_count * 0.15)) and bwd_pkts <= max(2, int(total_pkts * 0.15)):
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "high")
        heuristics.append("tcp_syn_burst")
        if str(pred.get("rf_labels", "BENIGN")).upper() == "BENIGN":
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "SYN-FLOOD"

    if looks_like_public_quic(flow_info):
        heuristics.append("public_quic_like")
        if str(pred.get("rf_labels", "BENIGN")).upper() == "UDP-FLOOD":
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "ANOMALOUS-UDP"
        if str(pred.get("ensemble_risk", "normal")).lower() == "high":
            pred["ensemble_risk"] = "low"

    if looks_like_benign_dns(flow_info):
        heuristics.append("benign_dns_like")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("UDP-FLOOD", "ANOMALOUS-UDP"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "BENIGN"
        pred["ensemble_risk"] = "normal"

    if looks_like_benign_industrial_polling(flow_info):
        heuristics.append("benign_industrial_polling")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("ANOMALOUS-TRAFFIC", "PORTSCAN", "SYN-FLOOD"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "BENIGN"
        pred["ensemble_risk"] = "normal"

    if looks_like_packet_injection(flow_info):
        pred["ae_anomaly"] = True
        pred["iso_risk"] = "high"
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "high")
        heuristics.append("packet_injection")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("BENIGN", "ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "PACKET-INJECTION"

    if "packet_injection" not in heuristics and looks_like_benign_web_session(flow_info) and rf_benign_prob >= 0.65:
        heuristics.append("benign_web_like")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "PORTSCAN", "SYN-FLOOD"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "BENIGN"
        pred["ensemble_risk"] = "normal"

    if rf_benign_prob >= 0.93 and not heuristics and proto == 6:
        heuristics.append("rf_benign_override")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "PORTSCAN", "SYN-FLOOD"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "BENIGN"
        pred["ensemble_risk"] = "normal"

    # Keep UDP flood detection conservative to avoid mislabeling ordinary DNS/video traffic.
    if proto == 17 and flow_pps >= 120 and total_pkts >= 24 and flow_bps >= 25000 and avg_pkt_size >= 250 and not looks_like_public_quic(flow_info):
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "high")
        heuristics.append("udp_packet_rate")
        if str(pred.get("rf_labels", "BENIGN")).upper() == "BENIGN":
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "UDP-FLOOD"

    if proto == 17 and dport in DNS_PORTS and total_pkts >= 50 and flow_pps >= 80 and not looks_like_benign_dns(flow_info):
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "medium")
        heuristics.append("dns_abuse")
        if str(pred.get("rf_labels", "BENIGN")).upper() in ("BENIGN", "ANOMALOUS-UDP"):
            pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
            pred["rf_labels"] = "DNS-ABUSE"

    agreement_count = sum(
        [
            bool(pred.get("ae_anomaly")),
            str(pred.get("ae_risk", "normal")).lower() in ("medium", "high"),
            str(pred.get("iso_risk", "normal")).lower() in ("medium", "high"),
            str(pred.get("kmeans_risk", "normal")).lower() in ("medium", "high"),
            is_suspicious_label(pred.get("rf_labels")),
            is_suspicious_label(pred.get("gbdt_labels")),
        ]
    )
    if agreement_count >= 3 and str(pred.get("ensemble_risk", "normal")).lower() in ("low", "medium"):
        pred["ensemble_risk"] = raise_risk(pred.get("ensemble_risk"), "high" if len(heuristics) >= 3 else "medium")
        heuristics.append("multi_model_agreement")

    return pred, heuristics


def infer_attack_type(flow_info: dict, pred: dict) -> str | None:
    proto = int(flow_info.get("proto", 0) or 0)
    src_ip = str(flow_info.get("src_ip", "") or "")
    dst_ip = str(flow_info.get("dst_ip", "") or "")
    sport = int(flow_info.get("sport", 0) or 0)
    dport = int(flow_info.get("dport", 0) or 0)
    ensemble = (pred.get("ensemble_risk") or "normal").lower()
    rf_label = str(pred.get("rf_labels", "BENIGN")).upper()
    gbdt_label = str(pred.get("gbdt_labels", "BENIGN")).upper()
    heuristics = set(pred.get("heuristics", []) or [])

    # Ignore local loopback chatter from the dashboard/browser/runtime itself,
    # but still allow explicit dashboard test traffic to port 5000.
    if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1" and 5000 not in (sport, dport):
        return None

    suspicious = (
        ensemble in ("medium", "high")
        or rf_label != "BENIGN"
        or gbdt_label != "BENIGN"
    )
    if not suspicious:
        return None

    if proto == 1:
        if looks_like_benign_local_icmp(flow_info):
            return None
        return "ICMP-FLOOD" if float(flow_info.get("flow_packets/s", 0) or 0) >= 50 else "ICMP-ANOMALY"
    if proto == 17:
        flow_pps = float(flow_info.get("flow_packets/s", 0) or 0)
        total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
        flow_bps = float(flow_info.get("flow_bytes/s", 0) or 0)
        avg_pkt_size = float(flow_info.get("average_packet_size", 0) or 0)
        if looks_like_benign_dns(flow_info):
            return None
        if looks_like_public_quic(flow_info):
            return "ANOMALOUS-UDP" if ensemble in ("medium", "high") else None
        if dport in DNS_PORTS and total_pkts >= 50 and flow_pps >= 80:
            return "DNS-ABUSE"
        return "UDP-FLOOD" if flow_pps >= 120 and total_pkts >= 24 and flow_bps >= 25000 and avg_pkt_size >= 250 else "ANOMALOUS-UDP"
    if proto == 6:
        syn_count = int(flow_info.get("syn_flag_count", 0) or 0)
        rst_count = int(flow_info.get("rst_flag_count", 0) or 0)
        ack_count = int(flow_info.get("ack_flag_count", 0) or 0)
        total_pkts = int(flow_info.get("total_fwd_packets", 0) or 0) + int(flow_info.get("total_backward_packets", 0) or 0)
        if looks_like_benign_industrial_polling(flow_info):
            return None
        if syn_count >= 20 and ensemble == "high":
            return "SYN-FLOOD"
        if dport in AUTH_PORTS and looks_like_service_probe(flow_info):
            return "AUTH-PROBE"
        if rst_count >= 2 and syn_count >= 1 and ack_count <= 1 and total_pkts <= 8:
            return "RST-SCAN"
        if "tcp_probe_cluster" in heuristics or "horizontal_scan" in heuristics:
            return "PORTSCAN"
    return "ANOMALOUS-TRAFFIC"


def severity_from_prediction(pred: dict) -> str:
    risk = str(pred.get("ensemble_risk", "normal")).lower()
    rf_label = str(pred.get("rf_labels", "BENIGN")).upper()
    gbdt_label = str(pred.get("gbdt_labels", "BENIGN")).upper()
    flow_key = pred.get("flow_key", {}) if isinstance(pred.get("flow_key"), dict) else {}
    src_ip = str(flow_key.get("src_ip", "") or "")
    dst_ip = str(flow_key.get("dst_ip", "") or "")
    sport = int(flow_key.get("sport", 0) or 0)
    dport = int(flow_key.get("dport", 0) or 0)

    if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1" and 5000 not in (sport, dport):
        heuristics = pred.get("heuristics", []) if isinstance(pred.get("heuristics"), list) else []
        if "tcp_probe" not in heuristics:
            return "normal"

    if looks_like_benign_industrial_polling(flow_key):
        return "normal"
    if looks_like_benign_local_icmp(flow_key):
        return "normal"

    rf_suspicious = rf_label not in ("BENIGN", "ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "MODELS_UNAVAILABLE", "ERROR")
    gbdt_suspicious = gbdt_label not in ("BENIGN", "ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "MODELS_UNAVAILABLE", "ERROR", "")
    heuristics = pred.get("heuristics", []) if isinstance(pred.get("heuristics"), list) else []
    model_votes = pred.get("model_votes", {}) or {}
    agreement_count = int(model_votes.get("agreement_count", 0))
    confidence_score = float(model_votes.get("confidence_score", 0) or 0)
    ppo_suspicious = bool(model_votes.get("ppo_suspicious"))
    gnn_suspicious = bool(model_votes.get("gnn_suspicious"))
    gnn_strong = bool(model_votes.get("gnn_strong"))
    anomaly_count = sum(
        [
            str(pred.get("ae_risk", "normal")).lower() in ("medium", "high"),
            str(pred.get("iso_risk", "normal")).lower() == "high",
            str(pred.get("kmeans_risk", "normal")).lower() == "high",
            ppo_suspicious,
            gnn_suspicious,
        ]
    )

    if "benign_dns_like" in heuristics or "benign_industrial_polling" in heuristics or "benign_web_like" in heuristics or "rf_benign_override" in heuristics or "benign_local_icmp" in heuristics:
        return "normal"

    if rf_label in ("SYN-FLOOD", "UDP-FLOOD"):
        return "high" if risk in ("high", "medium") or anomaly_count >= 1 or heuristics else "medium"
    if rf_label == "PACKET-INJECTION":
        return "high" if risk == "high" or agreement_count >= 2 or "packet_injection" in heuristics else "medium"
    if rf_label in ("DNS-ABUSE", "BRUTEFORCE", "ICMP-SWEEP"):
        return "high" if risk == "high" or agreement_count >= 3 or len(heuristics) >= 2 else "medium"
    if rf_label in ("AUTH-PROBE", "RST-SCAN"):
        return "medium" if risk in ("high", "medium", "low") or heuristics else "low"
    if rf_label == "PORTSCAN":
        if "horizontal_scan" in heuristics or "tcp_probe_cluster" in heuristics or "real_attack_match" in heuristics:
            return "high" if "horizontal_scan" in heuristics and (agreement_count >= 3 or confidence_score >= 3.0) else "medium"
        return "low" if "tcp_probe" in heuristics else "normal"
    if rf_label in ("ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "ICMP-ANOMALY"):
        if gnn_strong and anomaly_count >= 3:
            return "high"
        if confidence_score >= 5.0 or (gnn_suspicious and anomaly_count >= 3 and len(heuristics) >= 1) or len(heuristics) >= 2:
            return "medium"
        if agreement_count >= 3 or anomaly_count >= 2 or risk in ("medium", "high") or heuristics:
            return "low"
        return "normal"
    if risk == "high" and rf_suspicious and gbdt_suspicious:
        return "high"
    if agreement_count >= 5 and (rf_suspicious or gbdt_suspicious or anomaly_count >= 3 or gnn_strong):
        return "high"
    if agreement_count >= 4 and (rf_suspicious or gbdt_suspicious or anomaly_count >= 2 or gnn_suspicious or ppo_suspicious):
        return "high"
    if agreement_count >= 3 and (rf_suspicious or gbdt_suspicious or anomaly_count >= 2 or len(heuristics) >= 1 or gnn_suspicious or ppo_suspicious):
        return "medium"
    if risk in ("high", "medium") and (rf_suspicious or gbdt_suspicious or anomaly_count >= 2 or gnn_suspicious or ppo_suspicious):
        return "medium"
    if risk == "low" and (rf_suspicious or gbdt_suspicious or anomaly_count >= 1 or heuristics):
        return "low"
    if risk == "low" and anomaly_count >= 2:
        return "low"
    if risk == "medium" and anomaly_count >= 2:
        return "medium"
    return "normal"


def select_counterparty_ip(src_ip: str, dst_ip: str) -> str | None:
    local_ips = {"127.0.0.1", "::1"}
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            family_name = getattr(addr.family, "name", str(addr.family))
            if family_name in ("AF_INET", "AF_INET6"):
                local_ips.add(addr.address.split("%")[0])

    if src_ip not in local_ips:
        return src_ip
    if dst_ip not in local_ips:
        return dst_ip
    return None


def should_auto_block(record: dict) -> bool:
    severity = record.get("severity", "normal")
    return STATE.prevention_enabled and RISK_RANK.get(severity, 0) >= RISK_RANK.get(STATE.auto_block_threshold, 3)


def is_auto_block_entry(metadata: dict) -> bool:
    source = str(metadata.get("block_source", "") or "").lower()
    reason = str(metadata.get("reason", "") or "")
    return source == "auto" or reason.startswith("Auto-blocked")


def record_healing_event(ip: str, metadata: dict, result: dict, trigger: str, healed: bool) -> dict:
    event = {
        "ip": ip,
        "block_source": metadata.get("block_source", "unknown"),
        "trigger": trigger,
        "healed": healed,
        "requested_at": now_iso(),
        "blocked_at": metadata.get("blocked_at"),
        "scheduled_heal_at": metadata.get("heal_at"),
        "reason": metadata.get("reason"),
        "message": result.get("message", ""),
        "commands": result.get("commands", []),
    }
    if result.get("unblocked_at"):
        event["healed_at"] = result.get("unblocked_at")
    with STATE.lock:
        STATE.healed_events.appendleft(event)
    return event


def heal_block(ip: str, trigger: str = "manual", retry_seconds: int = 60) -> dict:
    with STATE.lock:
        metadata = dict(STATE.blocked_ips.get(ip, {}))

    if not metadata:
        return {
            "success": False,
            "ip": ip,
            "message": "No active block state found for that IP.",
            "trigger": trigger,
        }

    result = firewall_unblock_ip(ip)
    healed = bool(result.get("success"))
    result["trigger"] = trigger
    result["healed"] = healed
    result["healing_event"] = record_healing_event(ip, metadata, result, trigger, healed)

    with STATE.lock:
        if healed:
            STATE.blocked_ips.pop(ip, None)
        elif ip in STATE.blocked_ips:
            STATE.blocked_ips[ip]["last_heal_attempt_at"] = now_iso()
            STATE.blocked_ips[ip]["heal_status"] = "retry_pending"
            if trigger == "auto":
                STATE.blocked_ips[ip]["heal_at"] = iso_from_ts(now_ts() + retry_seconds)
    persist_results()
    return result


def maintain_healing() -> list[str]:
    with STATE.lock:
        if not STATE.healing_enabled:
            return []
        blocked_items = {ip: dict(metadata) for ip, metadata in STATE.blocked_ips.items()}

    due_ips: list[str] = []
    current_ts = now_ts()
    for ip, metadata in blocked_items.items():
        if not is_auto_block_entry(metadata):
            continue
        if str(metadata.get("status", "active")).lower() != "active":
            continue
        heal_at_ts = parse_iso_ts(metadata.get("heal_at"))
        if heal_at_ts is not None and heal_at_ts <= current_ts:
            due_ips.append(ip)

    healed_ips: list[str] = []
    for ip in due_ips:
        result = heal_block(ip, trigger="auto")
        if result.get("success"):
            healed_ips.append(ip)
    return healed_ips


def clear_auto_blocks() -> list[str]:
    removed: list[str] = []
    with STATE.lock:
        auto_ips = [ip for ip, metadata in STATE.blocked_ips.items() if isinstance(metadata, dict) and is_auto_block_entry(metadata)]

    for ip in auto_ips:
        result = heal_block(ip, trigger="disable_prevention")
        if result.get("success"):
            removed.append(ip)
    return removed


def add_alert(record: dict, title: str, message: str, blocked: bool = False) -> dict:
    rf_label = str(record.get("rf_labels", "BENIGN") or "BENIGN").upper()
    flow_key = record.get("flow_key", {}) if isinstance(record.get("flow_key"), dict) else {}
    src_ip = str(flow_key.get("src_ip", "") or "")
    dst_ip = str(flow_key.get("dst_ip", "") or "")
    dedupe_dport = flow_key.get("dport")
    dedupe_pair = (src_ip, dst_ip)
    dedupe_window = 12

    if rf_label in ("PORTSCAN", "ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP"):
        dedupe_pair = tuple(sorted((src_ip, dst_ip)))
    if rf_label == "PORTSCAN":
        dedupe_dport = 0
        dedupe_window = 45
    elif rf_label in ("ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP"):
        dedupe_window = 30

    alert_key = (
        rf_label,
        dedupe_pair[0],
        dedupe_pair[1],
        dedupe_dport,
        record.get("severity", "normal"),
    )
    current_ts = now_ts()
    with STATE.lock:
        last_seen = STATE.recent_alerts.get(alert_key)
        if last_seen is not None and current_ts - last_seen < dedupe_window:
            return {}
        STATE.recent_alerts[alert_key] = current_ts

    alert = {
        "timestamp": now_iso(),
        "title": title,
        "message": message,
        "severity": record.get("severity", "normal"),
        "rf_label": record.get("rf_labels", "BENIGN"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "candidate_block_ip": record.get("candidate_block_ip"),
        "blocked": blocked,
    }
    with STATE.lock:
        STATE.alerts.appendleft(alert)
    return alert


def classify_model_votes(pred: dict) -> dict:
    iso_risk = str(pred.get("iso_risk", "normal")).lower()
    km_risk = str(pred.get("kmeans_risk", "normal")).lower()
    ae_risk = str(pred.get("ae_risk", "normal")).lower()
    ae_flag = bool(pred.get("ae_anomaly"))
    rf_label = str(pred.get("rf_labels", "BENIGN")).upper()
    gbdt_label = str(pred.get("gbdt_labels", "BENIGN")).upper()
    ppo_risk = str(pred.get("ppo_risk", "normal")).lower()
    gnn_label = str(pred.get("gnn_label", "normal")).lower()
    gnn_attack_prob = float(pred.get("gnn_attack_prob", 0) or 0)
    generic_labels = ("BENIGN", "ANOMALOUS-TRAFFIC", "ANOMALOUS-UDP", "ICMP-ANOMALY", "MODELS_UNAVAILABLE", "ERROR")
    rf_suspicious = rf_label not in generic_labels
    gbdt_suspicious = gbdt_label not in generic_labels + ("",)
    ppo_suspicious = ppo_risk in ("medium", "high", "attack")
    gnn_suspicious = gnn_label == "attack" and gnn_attack_prob >= 0.6
    gnn_strong = gnn_label == "attack" and gnn_attack_prob >= 0.85
    agreement_count = sum(
        [
            ae_flag,
            iso_risk in ("medium", "high"),
            km_risk in ("medium", "high"),
            rf_suspicious,
            gbdt_suspicious,
            ppo_suspicious,
            gnn_suspicious,
        ]
    )
    confidence_score = round(
        (
            (1.0 if ae_flag else 0.0)
            + (1.0 if iso_risk == "high" else 0.5 if iso_risk == "medium" else 0.0)
            + (1.0 if km_risk == "high" else 0.5 if km_risk == "medium" else 0.0)
            + (1.2 if rf_suspicious else 0.0)
            + (1.0 if gbdt_suspicious else 0.0)
            + (0.8 if ppo_risk == "high" else 0.5 if ppo_suspicious else 0.0)
            + (1.0 if gnn_strong else 0.6 if gnn_suspicious else 0.0)
        ),
        2,
    )
    return {
        "ae_flag": ae_flag,
        "ae_risk": ae_risk,
        "iso_suspicious": iso_risk in ("medium", "high"),
        "kmeans_suspicious": km_risk in ("medium", "high"),
        "rf_suspicious": rf_suspicious,
        "gbdt_suspicious": gbdt_suspicious,
        "ppo_suspicious": ppo_suspicious,
        "ppo_risk": ppo_risk,
        "gnn_suspicious": gnn_suspicious,
        "gnn_strong": gnn_strong,
        "gnn_attack_prob": gnn_attack_prob,
        "agreement_count": agreement_count,
        "confidence_score": confidence_score,
    }


def match_attack_run(record: dict) -> dict | None:
    record_time = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).timestamp()
    proto = int(record["flow_key"]["proto"])
    target_ip = record["flow_key"]["dst_ip"]
    dport = int(record["flow_key"]["dport"])

    with STATE.lock:
        runs = list(STATE.attack_runs)

    for run in runs:
        start_ts = run["started_ts"]
        end_ts = run.get("finished_ts") or start_ts
        time_matches = start_ts - 2 <= record_time <= end_ts + 20
        proto_matches = run.get("proto") in (None, proto)
        ip_matches = run.get("target_ip") == target_ip or run.get("target_ip") == record["flow_key"]["src_ip"]
        port_matches = run.get("target_port") in (None, 0, dport) or run["attack_type"] == "port_scan"
        if time_matches and proto_matches and ip_matches and port_matches:
            return run
    return None


def promote_real_attack_record(record: dict, label: str, severity: str, extra_heuristics: list[str] | None = None) -> dict:
    heuristics = list(record.get("heuristics", []) or [])
    for item in extra_heuristics or []:
        if item not in heuristics:
            heuristics.append(item)
    record["heuristics"] = heuristics

    current_severity = str(record.get("severity", "normal") or "normal").lower()
    if RISK_RANK.get(severity, 0) > RISK_RANK.get(current_severity, 0):
        record["severity"] = severity

    current_ensemble = str(record.get("ensemble_risk", "normal") or "normal").lower()
    if RISK_RANK.get(severity, 0) > RISK_RANK.get(current_ensemble, 0):
        record["ensemble_risk"] = severity

    current_label = str(record.get("rf_labels", "BENIGN") or "BENIGN").upper()
    if current_label != label:
        record["rf_model_label"] = record.get("rf_labels", "BENIGN")
        record["rf_labels"] = label

    return record


def correlate_attack_patterns(records: list[dict]) -> list[dict]:
    if not records:
        return records

    probe_groups: dict[tuple[str, str], list[dict]] = {}
    syn_groups: dict[tuple[str, str, int], list[dict]] = {}
    udp_groups: dict[tuple[str, str, int], list[dict]] = {}
    auth_probe_groups: dict[tuple[str, str, int], list[dict]] = {}
    icmp_groups: dict[str, list[dict]] = {}
    src_portscan_groups: dict[str, list[dict]] = {}
    matched_run_groups: dict[str, list[dict]] = {}
    injection_groups: dict[tuple[tuple[str, str], int], list[dict]] = {}

    for record in records:
        flow_key = record.get("flow_key", {}) if isinstance(record.get("flow_key"), dict) else {}
        src_ip = str(flow_key.get("src_ip", "") or "")
        dst_ip = str(flow_key.get("dst_ip", "") or "")
        sport = int(flow_key.get("sport", 0) or 0)
        dport = int(flow_key.get("dport", 0) or 0)
        proto = int(flow_key.get("proto", 0) or 0)
        heuristics = set(record.get("heuristics", []) or [])

        run_id = str(record.get("attack_run_id", "") or "")
        if run_id:
            matched_run_groups.setdefault(run_id, []).append(record)

        if proto == 6 and "tcp_probe" in heuristics:
            probe_groups.setdefault((src_ip, dst_ip), []).append(record)
            src_portscan_groups.setdefault(src_ip, []).append(record)

        if proto == 6:
            syn_groups.setdefault((src_ip, dst_ip, dport), []).append(record)
            if dport in AUTH_PORTS and ("auth_probe" in heuristics or "tcp_probe" in heuristics):
                auth_probe_groups.setdefault((src_ip, dst_ip, dport), []).append(record)
            service_port = dport if dport in (80, 8080, 8000) else (sport if sport in (80, 8080, 8000) else 0)
            if service_port:
                pair_key = (tuple(sorted((src_ip, dst_ip))), service_port)
                injection_groups.setdefault(pair_key, []).append(record)

        if proto == 17:
            udp_groups.setdefault((src_ip, dst_ip, dport), []).append(record)

        if proto == 1:
            icmp_groups.setdefault(src_ip, []).append(record)

    for records_in_group in matched_run_groups.values():
        attack_type = str(records_in_group[0].get("attack_run_label", "") or "").upper()
        attack_id = str(records_in_group[0].get("attack_run_id", "") or "")
        if not attack_id:
            continue
        run = None
        with STATE.lock:
            for item in STATE.attack_runs:
                if item.get("id") == attack_id:
                    run = dict(item)
                    break
        attack_type = str((run or {}).get("attack_type", "") or "").lower()
        if attack_type == "syn_flood":
            for record in records_in_group:
                promote_real_attack_record(record, "SYN-FLOOD", "high", ["real_attack_match", "tcp_syn_burst"])
        elif attack_type == "udp_flood":
            for record in records_in_group:
                promote_real_attack_record(record, "UDP-FLOOD", "high", ["real_attack_match", "udp_packet_rate"])
        elif attack_type == "port_scan":
            for record in records_in_group:
                promote_real_attack_record(record, "PORTSCAN", "medium", ["real_attack_match", "tcp_probe_cluster"])

    for grouped in probe_groups.values():
        unique_ports = {int((record.get("flow_key", {}) or {}).get("dport", 0) or 0) for record in grouped}
        src_ip = str((grouped[0].get("flow_key", {}) or {}).get("src_ip", "") or "") if grouped else ""
        dst_ip = str((grouped[0].get("flow_key", {}) or {}).get("dst_ip", "") or "") if grouped else ""
        with STATE.lock:
            recent_probes = [
                item for item in list(STATE.results)[:160]
                if int((item.get("flow_key", {}) or {}).get("proto", 0) or 0) == 6
                and str((item.get("flow_key", {}) or {}).get("src_ip", "") or "") == src_ip
                and str((item.get("flow_key", {}) or {}).get("dst_ip", "") or "") == dst_ip
                and "tcp_probe" in set(item.get("heuristics", []) or [])
            ]
        unique_ports.update(int((item.get("flow_key", {}) or {}).get("dport", 0) or 0) for item in recent_probes)
        if len(unique_ports) >= 10:
            for record in grouped:
                promote_real_attack_record(record, "PORTSCAN", "medium", ["tcp_probe_cluster"])

    for src_ip, grouped in src_portscan_groups.items():
        unique_targets = {(str((record.get("flow_key", {}) or {}).get("dst_ip", "") or ""), int((record.get("flow_key", {}) or {}).get("dport", 0) or 0)) for record in grouped}
        if len(unique_targets) >= 12:
            for record in grouped:
                promote_real_attack_record(record, "PORTSCAN", "high", ["horizontal_scan"])

    for grouped in auth_probe_groups.values():
        total_attempts = len(grouped)
        total_syn = sum(int(record.get("syn_flag_count", 0) or 0) for record in grouped)
        if total_attempts >= 8 or total_syn >= 12:
            for record in grouped:
                promote_real_attack_record(record, "BRUTEFORCE", "high" if total_attempts >= 12 else "medium", ["auth_bruteforce"])

    for grouped in injection_groups.values():
        candidate_records = []
        strong_hits = 0
        sum_bwd_seq_dup = 0
        sum_fwd_ack_dup = 0
        sum_bwd_ack_dup = 0
        for record in grouped:
            bwd_ttl_unique = int(record.get("bwd_ttl_unique_count", 0) or 0)
            bwd_seq_dup = int(record.get("bwd_tcp_seq_dup_count", 0) or 0)
            fwd_ack_dup = int(record.get("fwd_tcp_ack_dup_count", 0) or 0)
            bwd_ack_dup = int(record.get("bwd_tcp_ack_dup_count", 0) or 0)
            bwd_synack = int(record.get("bwd_synack_count", 0) or 0)
            bwd_http_status = int(record.get("bwd_http_status_count", 0) or 0)
            candidate = bwd_ttl_unique >= 2 and (bwd_seq_dup >= 1 or bwd_http_status >= 1 or bwd_synack >= 1)
            if not candidate:
                continue
            candidate_records.append(record)
            sum_bwd_seq_dup += bwd_seq_dup
            sum_fwd_ack_dup += fwd_ack_dup
            sum_bwd_ack_dup += bwd_ack_dup
            if bwd_http_status >= 2 or bwd_synack >= 2 or bwd_ttl_unique >= 3:
                strong_hits += 1

        if len(candidate_records) >= 3 and (strong_hits >= 1 or (sum_bwd_seq_dup >= 4 and (sum_fwd_ack_dup >= 8 or sum_bwd_ack_dup >= 12))):
            severity = "high" if strong_hits >= 1 else "medium"
            for record in candidate_records:
                promote_real_attack_record(record, "PACKET-INJECTION", severity, ["packet_injection_cluster"])

    for grouped in syn_groups.values():
        total_syn = sum(int(record.get("syn_flag_count", 0) or 0) for record in grouped)
        total_packets = sum(int(record.get("total_fwd_packets", 0) or 0) + int(record.get("total_backward_packets", 0) or 0) for record in grouped)
        total_ack = sum(int(record.get("ack_flag_count", 0) or 0) for record in grouped)
        total_bwd = sum(int(record.get("total_backward_packets", 0) or 0) for record in grouped)
        src_ip = str((grouped[0].get("flow_key", {}) or {}).get("src_ip", "") or "") if grouped else ""
        dst_ip = str((grouped[0].get("flow_key", {}) or {}).get("dst_ip", "") or "") if grouped else ""
        dport = int((grouped[0].get("flow_key", {}) or {}).get("dport", 0) or 0) if grouped else 0
        with STATE.lock:
            recent_syn = [
                item for item in list(STATE.results)[:120]
                if int((item.get("flow_key", {}) or {}).get("proto", 0) or 0) == 6
                and str((item.get("flow_key", {}) or {}).get("src_ip", "") or "") == src_ip
                and str((item.get("flow_key", {}) or {}).get("dst_ip", "") or "") == dst_ip
                and int((item.get("flow_key", {}) or {}).get("dport", 0) or 0) == dport
            ]
        total_syn += sum(int(item.get("syn_flag_count", 0) or 0) for item in recent_syn)
        total_packets += sum(int(item.get("total_fwd_packets", 0) or 0) + int(item.get("total_backward_packets", 0) or 0) for item in recent_syn)
        total_ack += sum(int(item.get("ack_flag_count", 0) or 0) for item in recent_syn)
        total_bwd += sum(int(item.get("total_backward_packets", 0) or 0) for item in recent_syn)
        if total_syn >= 40 and total_packets >= 40 and total_ack <= max(3, int(total_syn * 0.2)) and total_bwd <= max(4, int(total_packets * 0.2)):
            for record in grouped:
                promote_real_attack_record(record, "SYN-FLOOD", "high", ["tcp_syn_burst"])

    for grouped in udp_groups.values():
        total_packets = sum(int(record.get("total_fwd_packets", 0) or 0) + int(record.get("total_backward_packets", 0) or 0) for record in grouped)
        total_bps = sum(float(record.get("flow_bytes/s", 0) or 0) for record in grouped)
        avg_size = float(np.mean([float(record.get("average_packet_size", 0) or 0) for record in grouped])) if grouped else 0.0
        src_ip = str((grouped[0].get("flow_key", {}) or {}).get("src_ip", "") or "") if grouped else ""
        dst_ip = str((grouped[0].get("flow_key", {}) or {}).get("dst_ip", "") or "") if grouped else ""
        sport = int((grouped[0].get("flow_key", {}) or {}).get("sport", 0) or 0) if grouped else 0
        dport = int((grouped[0].get("flow_key", {}) or {}).get("dport", 0) or 0) if grouped else 0
        if ((is_privateish_ip(src_ip) and is_public_ip(dst_ip)) or (is_public_ip(src_ip) and is_privateish_ip(dst_ip))) and 443 in (sport, dport):
            continue
        with STATE.lock:
            recent_udp = [
                item for item in list(STATE.results)[:120]
                if int((item.get("flow_key", {}) or {}).get("proto", 0) or 0) == 17
                and str((item.get("flow_key", {}) or {}).get("src_ip", "") or "") == src_ip
                and str((item.get("flow_key", {}) or {}).get("dst_ip", "") or "") == dst_ip
                and int((item.get("flow_key", {}) or {}).get("dport", 0) or 0) == dport
            ]
        total_packets += sum(int(item.get("total_fwd_packets", 0) or 0) + int(item.get("total_backward_packets", 0) or 0) for item in recent_udp)
        total_bps += sum(float(item.get("flow_bytes/s", 0) or 0) for item in recent_udp)
        if recent_udp:
            avg_size = float(np.mean(
                [avg_size] + [float(item.get("average_packet_size", 0) or 0) for item in recent_udp if float(item.get("average_packet_size", 0) or 0) > 0]
            ))
        if total_packets >= 24 and total_bps >= 25000 and avg_size >= 250:
            for record in grouped:
                promote_real_attack_record(record, "UDP-FLOOD", "high", ["udp_packet_rate"])

    for src_ip, grouped in icmp_groups.items():
        unique_targets = {str((record.get("flow_key", {}) or {}).get("dst_ip", "") or "") for record in grouped if is_privateish_ip(str((record.get("flow_key", {}) or {}).get("dst_ip", "") or ""))}
        total_packets = sum(int(record.get("total_fwd_packets", 0) or 0) + int(record.get("total_backward_packets", 0) or 0) for record in grouped)
        if len(unique_targets) >= 6 and total_packets >= 12:
            for record in grouped:
                promote_real_attack_record(record, "ICMP-SWEEP", "medium", ["icmp_sweep"])

    return records


def update_attack_run_detection(run_id: str, record: dict) -> None:
    with STATE.lock:
        for run in STATE.attack_runs:
            if run["id"] != run_id:
                continue
            run["matched_flows"] = int(run.get("matched_flows", 0)) + 1
            if record.get("severity") in ("high", "medium") or record.get("ae_anomaly"):
                run["detection_count"] = int(run.get("detection_count", 0)) + 1
                if run.get("first_detection_ts") is None:
                    first_detection_ts = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00")).timestamp()
                    run["first_detection_ts"] = first_detection_ts
                    run["detection_latency_ms"] = round((first_detection_ts - run["started_ts"]) * 1000, 2)
                    run["first_detected_label"] = record.get("rf_labels", "UNKNOWN")
            if record.get("prevention_result", {}).get("success") and run.get("first_prevention_ts") is None:
                blocked_at = record["prevention_result"].get("blocked_at")
                if blocked_at:
                    blocked_ts = datetime.fromisoformat(blocked_at.replace("Z", "+00:00")).timestamp()
                    run["first_prevention_ts"] = blocked_ts
                    run["prevention_latency_ms"] = round((blocked_ts - run["started_ts"]) * 1000, 2)
                    run["blocked_ip"] = record.get("candidate_block_ip")
            break


def flatten_result(record: dict) -> dict:
    row = dict(record)
    flow_key = row.pop("flow_key", {})
    for key, value in flow_key.items():
        row[f"flow_{key}"] = value
    row["heuristics"] = ",".join(row.get("heuristics", []))
    return row


def feature_rows_from_packets(packets) -> list[dict]:
    current_flows: dict[tuple, dict] = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        proto = int(pkt[IP].proto)
        sport = int(pkt.sport) if TCP in pkt or UDP in pkt else 0
        dport = int(pkt.dport) if TCP in pkt or UDP in pkt else 0
        ip_pair = tuple(sorted((pkt[IP].src, pkt[IP].dst)))
        port_pair = tuple(sorted((sport, dport)))
        flow_key = ip_pair + port_pair + (proto,)

        if flow_key not in current_flows:
            current_flows[flow_key] = {
                "flow_initiator_ip": pkt[IP].src,
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "timestamps": [],
                "fwd_timestamps": [],
                "bwd_timestamps": [],
                "fwd_pkt_lengths": [],
                "bwd_pkt_lengths": [],
                "fwd_header_lengths": [],
                "bwd_header_lengths": [],
                "fin_flag_count": 0,
                "syn_flag_count": 0,
                "rst_flag_count": 0,
                "psh_flag_count": 0,
                "ack_flag_count": 0,
                "urg_flag_count": 0,
                "ece_flag_count": 0,
                "cwe_flag_count": 0,
                "fwd_psh_flags": 0,
                "bwd_psh_flags": 0,
                "fwd_urg_flags": 0,
                "bwd_urg_flags": 0,
                "fwd_synack_count": 0,
                "bwd_synack_count": 0,
                "act_data_pkt_fwd": 0,
                "init_win_bytes_forward": 0,
                "init_win_bytes_backward": 0,
                "fwd_ttls": set(),
                "bwd_ttls": set(),
                "fwd_seqs": [],
                "bwd_seqs": [],
                "fwd_acks": [],
                "bwd_acks": [],
                "fwd_http_statuses": set(),
                "bwd_http_statuses": set(),
            }

        flow = current_flows[flow_key]
        timestamp = float(pkt.time)
        flow["timestamps"].append(timestamp)

        pkt_len = len(pkt)
        ip_ihl = int(getattr(pkt[IP], "ihl", 5) or 5)
        header_len = ip_ihl * 4
        if TCP in pkt:
            tcp_dataofs = int(getattr(pkt[TCP], "dataofs", 5) or 5)
            header_len += tcp_dataofs * 4
        elif UDP in pkt:
            header_len += 8

        payload_len = pkt_len - header_len if pkt_len > header_len else 0
        ttl = int(getattr(pkt[IP], "ttl", 0) or 0)
        is_forward = pkt[IP].src == flow["flow_initiator_ip"]

        if is_forward:
            flow["fwd_pkt_lengths"].append(pkt_len)
            flow["fwd_timestamps"].append(timestamp)
            flow["fwd_header_lengths"].append(header_len)
            flow["fwd_ttls"].add(ttl)
            if payload_len > 0:
                flow["act_data_pkt_fwd"] += 1
            if TCP in pkt:
                flow["init_win_bytes_forward"] = int(getattr(pkt[TCP], "window", 0) or 0)
        else:
            flow["bwd_pkt_lengths"].append(pkt_len)
            flow["bwd_timestamps"].append(timestamp)
            flow["bwd_header_lengths"].append(header_len)
            flow["bwd_ttls"].add(ttl)
            if TCP in pkt:
                flow["init_win_bytes_backward"] = int(getattr(pkt[TCP], "window", 0) or 0)

        if TCP in pkt:
            flags = str(pkt[TCP].flags)
            seq = int(getattr(pkt[TCP], "seq", 0) or 0)
            ack = int(getattr(pkt[TCP], "ack", 0) or 0)
            if is_forward:
                flow["fwd_seqs"].append(seq)
                flow["fwd_acks"].append(ack)
            else:
                flow["bwd_seqs"].append(seq)
                flow["bwd_acks"].append(ack)

            if "F" in flags:
                flow["fin_flag_count"] += 1
            if "S" in flags:
                flow["syn_flag_count"] += 1
            if "R" in flags:
                flow["rst_flag_count"] += 1
            if "P" in flags:
                flow["psh_flag_count"] += 1
                flow["fwd_psh_flags" if is_forward else "bwd_psh_flags"] += 1
            if "A" in flags:
                flow["ack_flag_count"] += 1
                if "S" in flags:
                    flow["fwd_synack_count" if is_forward else "bwd_synack_count"] += 1
            if "U" in flags:
                flow["urg_flag_count"] += 1
                flow["fwd_urg_flags" if is_forward else "bwd_urg_flags"] += 1
            if "E" in flags:
                flow["ece_flag_count"] += 1
            if "C" in flags:
                flow["cwe_flag_count"] += 1

            if payload_len > 0 and Raw is not None and pkt.haslayer(Raw):
                try:
                    payload = bytes(pkt[Raw].load[:64])
                    if payload.startswith(b"HTTP/"):
                        parts = payload.split(None, 2)
                        if len(parts) >= 2:
                            status_code = int(parts[1].decode("ascii", errors="ignore"))
                            if 100 <= status_code <= 599:
                                flow["fwd_http_statuses" if is_forward else "bwd_http_statuses"].add(status_code)
                except Exception:
                    pass

    def get_iat_stats(times):
        if len(times) > 1:
            iats = np.diff(times) * 1_000_000
            return float(np.sum(iats)), float(np.mean(iats)), float(np.std(iats)), float(np.max(iats)), float(np.min(iats))
        return 0.0, 0.0, 0.0, 0.0, 0.0

    rows = []
    for flow_data in current_flows.values():
        t_arr = sorted(flow_data["timestamps"])
        fwd_t_arr = sorted(flow_data["fwd_timestamps"])
        bwd_t_arr = sorted(flow_data["bwd_timestamps"])
        fwd_lens = flow_data["fwd_pkt_lengths"]
        bwd_lens = flow_data["bwd_pkt_lengths"]
        all_lens = fwd_lens + bwd_lens

        if not t_arr or not all_lens:
            continue

        duration_sec = t_arr[-1] - t_arr[0] if len(t_arr) > 1 else 0.001
        flow_duration = duration_sec * 1_000_000 if duration_sec > 0 else 1.0
        active_times = []
        idle_times = []
        current_active_start = t_arr[0]
        last_pkt_time = t_arr[0]
        for t in t_arr[1:]:
            if t - last_pkt_time > 1.0:
                active_times.append((last_pkt_time - current_active_start) * 1_000_000)
                idle_times.append((t - last_pkt_time) * 1_000_000)
                current_active_start = t
            last_pkt_time = t
        active_times.append((last_pkt_time - current_active_start) * 1_000_000)

        fwd_seq_dup_count = max(0, len(flow_data["fwd_seqs"]) - len(set(flow_data["fwd_seqs"])))
        bwd_seq_dup_count = max(0, len(flow_data["bwd_seqs"]) - len(set(flow_data["bwd_seqs"])))
        fwd_ack_dup_count = max(0, len(flow_data["fwd_acks"]) - len(set(flow_data["fwd_acks"])))
        bwd_ack_dup_count = max(0, len(flow_data["bwd_acks"]) - len(set(flow_data["bwd_acks"])))

        row = {
            "src_ip": flow_data["src_ip"],
            "dst_ip": flow_data["dst_ip"],
            "sport": flow_data["sport"],
            "dport": flow_data["dport"],
            "destination_port": flow_data["dport"],
            "proto": flow_data["proto"],
            "flow_duration": flow_duration,
            "total_fwd_packets": len(fwd_lens),
            "total_backward_packets": len(bwd_lens),
            "total_length_of_fwd_packets": sum(fwd_lens),
            "total_length_of_bwd_packets": sum(bwd_lens),
            "fwd_packet_length_max": max(fwd_lens) if fwd_lens else 0,
            "fwd_packet_length_min": min(fwd_lens) if fwd_lens else 0,
            "fwd_packet_length_mean": float(np.mean(fwd_lens)) if fwd_lens else 0.0,
            "fwd_packet_length_std": float(np.std(fwd_lens)) if len(fwd_lens) > 1 else 0.0,
            "bwd_packet_length_max": max(bwd_lens) if bwd_lens else 0,
            "bwd_packet_length_min": min(bwd_lens) if bwd_lens else 0,
            "bwd_packet_length_mean": float(np.mean(bwd_lens)) if bwd_lens else 0.0,
            "bwd_packet_length_std": float(np.std(bwd_lens)) if len(bwd_lens) > 1 else 0.0,
            "max_packet_length": max(all_lens) if all_lens else 0,
            "min_packet_length": min(all_lens) if all_lens else 0,
            "packet_length_mean": float(np.mean(all_lens)) if all_lens else 0.0,
            "packet_length_std": float(np.std(all_lens)) if len(all_lens) > 1 else 0.0,
            "packet_length_variance": float(np.var(all_lens)) if len(all_lens) > 1 else 0.0,
            "flow_bytes/s": sum(all_lens) / (flow_duration / 1_000_000),
            "flow_packets/s": len(all_lens) / (flow_duration / 1_000_000),
            "fin_flag_count": flow_data["fin_flag_count"],
            "syn_flag_count": flow_data["syn_flag_count"],
            "rst_flag_count": flow_data["rst_flag_count"],
            "psh_flag_count": flow_data["psh_flag_count"],
            "ack_flag_count": flow_data["ack_flag_count"],
            "urg_flag_count": flow_data["urg_flag_count"],
            "ece_flag_count": flow_data["ece_flag_count"],
            "cwe_flag_count": flow_data["cwe_flag_count"],
            "fwd_psh_flags": flow_data["fwd_psh_flags"],
            "bwd_psh_flags": flow_data["bwd_psh_flags"],
            "fwd_urg_flags": flow_data["fwd_urg_flags"],
            "bwd_urg_flags": flow_data["bwd_urg_flags"],
            "act_data_pkt_fwd": flow_data["act_data_pkt_fwd"],
            "init_win_bytes_forward": flow_data["init_win_bytes_forward"],
            "init_win_bytes_backward": flow_data["init_win_bytes_backward"],
            "fwd_ttl_unique_count": len(flow_data["fwd_ttls"]),
            "bwd_ttl_unique_count": len(flow_data["bwd_ttls"]),
            "fwd_tcp_seq_dup_count": fwd_seq_dup_count,
            "bwd_tcp_seq_dup_count": bwd_seq_dup_count,
            "fwd_tcp_ack_dup_count": fwd_ack_dup_count,
            "bwd_tcp_ack_dup_count": bwd_ack_dup_count,
            "fwd_synack_count": flow_data["fwd_synack_count"],
            "bwd_synack_count": flow_data["bwd_synack_count"],
            "fwd_http_status_count": len(flow_data["fwd_http_statuses"]),
            "bwd_http_status_count": len(flow_data["bwd_http_statuses"]),
            "active_mean": float(np.mean(active_times)) if active_times else 0.0,
            "active_std": float(np.std(active_times)) if len(active_times) > 1 else 0.0,
            "active_max": float(np.max(active_times)) if active_times else 0.0,
            "idle_std": float(np.std(idle_times)) if len(idle_times) > 1 else 0.0,
        }

        f_iat_tot, f_iat_mean, f_iat_std, f_iat_max, f_iat_min = get_iat_stats(t_arr)
        row.update(
            {
                "flow_iat_total": f_iat_tot,
                "flow_iat_mean": f_iat_mean,
                "flow_iat_std": f_iat_std,
                "flow_iat_max": f_iat_max,
                "flow_iat_min": f_iat_min,
            }
        )

        fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = get_iat_stats(fwd_t_arr)
        row.update(
            {
                "fwd_iat_total": fwd_iat_tot,
                "fwd_iat_mean": fwd_iat_mean,
                "fwd_iat_std": fwd_iat_std,
                "fwd_iat_max": fwd_iat_max,
                "fwd_iat_min": fwd_iat_min,
            }
        )

        bwd_iat_tot, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = get_iat_stats(bwd_t_arr)
        row.update(
            {
                "bwd_iat_total": bwd_iat_tot,
                "bwd_iat_mean": bwd_iat_mean,
                "bwd_iat_std": bwd_iat_std,
                "bwd_iat_max": bwd_iat_max,
                "bwd_iat_min": bwd_iat_min,
                "fwd_header_length": sum(flow_data["fwd_header_lengths"]),
                "bwd_header_length": sum(flow_data["bwd_header_lengths"]),
                "fwd_packets/s": len(fwd_lens) / (flow_duration / 1_000_000),
                "bwd_packets/s": len(bwd_lens) / (flow_duration / 1_000_000),
                "down/up_ratio": len(bwd_lens) / len(fwd_lens) if len(fwd_lens) > 0 else 0,
                "average_packet_size": sum(all_lens) / len(all_lens) if all_lens else 0.0,
                "avg_fwd_segment_size": float(np.mean(fwd_lens)) if fwd_lens else 0.0,
                "avg_bwd_segment_size": float(np.mean(bwd_lens)) if bwd_lens else 0.0,
                "min_seg_size_forward": min(flow_data["fwd_header_lengths"]) if flow_data["fwd_header_lengths"] else 0,
                "subflow_fwd_packets": len(fwd_lens),
                "subflow_fwd_bytes": sum(fwd_lens),
                "subflow_bwd_packets": len(bwd_lens),
                "subflow_bwd_bytes": sum(bwd_lens),
            }
        )

        rows.append(row)
    return rows


def score_rows(rows: list[dict], fast_mode: bool = False) -> list[dict]:
    if not rows:
        return []

    if MODELS is not None and PREDICT_ALL is not None:
        try:
            models_for_prediction = MODELS
            if fast_mode:
                models_for_prediction = {key: value for key, value in MODELS.items() if key != "gbdt"}
            preds = PREDICT_ALL(models_for_prediction, pd.DataFrame(rows))
        except Exception as exc:
            print(f"Prediction error: {exc}")
            preds = [{"ensemble_risk": "error", "ae_anomaly": False, "iso_risk": "error", "kmeans_risk": "error", "rf_labels": "ERROR"} for _ in rows]
    else:
        preds = [{"ensemble_risk": "error", "ae_anomaly": False, "iso_risk": "error", "kmeans_risk": "error", "rf_labels": "MODELS_UNAVAILABLE"} for _ in rows]

    scored_records = []
    for flow_info, pred in zip(rows, preds):
        raw_pred = {
            "ae_score": pred.get("ae_score"),
            "ae_anomaly": pred.get("ae_anomaly"),
            "ae_risk": pred.get("ae_risk"),
            "iso_score": pred.get("iso_score"),
            "iso_risk": pred.get("iso_risk"),
            "kmeans_score": pred.get("kmeans_score"),
            "kmeans_risk": pred.get("kmeans_risk"),
            "rf_labels": pred.get("rf_labels"),
            "gbdt_labels": pred.get("gbdt_labels"),
            "ppo_risk": pred.get("ppo_risk"),
            "gnn_label": pred.get("gnn_label"),
            "gnn_attack_prob": pred.get("gnn_attack_prob"),
        }
        pred, heuristics = apply_traffic_heuristics(flow_info, pred)
        pred["heuristics"] = heuristics
        if str(pred.get("rf_labels", "BENIGN")).upper() == "BENIGN":
            inferred = infer_attack_type(flow_info, pred)
            if inferred:
                pred["rf_model_label"] = pred.get("rf_labels", "BENIGN")
                pred["rf_labels"] = inferred

        pred["model_votes"] = classify_model_votes(pred)
        pred["flow_key"] = {
            "src_ip": flow_info.get("src_ip"),
            "dst_ip": flow_info.get("dst_ip"),
            "sport": int(flow_info.get("sport", 0) or 0),
            "dport": int(flow_info.get("dport", 0) or 0),
            "proto": int(flow_info.get("proto", 0) or 0),
        }
        severity = severity_from_prediction(pred)
        src_ip = flow_info.get("src_ip")
        dst_ip = flow_info.get("dst_ip")
        candidate_ip = select_counterparty_ip(src_ip, dst_ip)

        record = {
            "timestamp": now_iso(),
            "flow_key": pred["flow_key"],
            "proto_name": PROTO_NAMES.get(int(flow_info.get("proto", 0) or 0), f"Proto {flow_info.get('proto', 0)}"),
            "total_fwd_packets": int(flow_info.get("total_fwd_packets", 0) or 0),
            "total_backward_packets": int(flow_info.get("total_backward_packets", 0) or 0),
            "flow_bytes/s": float(flow_info.get("flow_bytes/s", 0) or 0),
            "flow_packets/s": float(flow_info.get("flow_packets/s", 0) or 0),
            "average_packet_size": float(flow_info.get("average_packet_size", 0) or 0),
            "syn_flag_count": int(flow_info.get("syn_flag_count", 0) or 0),
            "fwd_ttl_unique_count": int(flow_info.get("fwd_ttl_unique_count", 0) or 0),
            "bwd_ttl_unique_count": int(flow_info.get("bwd_ttl_unique_count", 0) or 0),
            "fwd_tcp_seq_dup_count": int(flow_info.get("fwd_tcp_seq_dup_count", 0) or 0),
            "bwd_tcp_seq_dup_count": int(flow_info.get("bwd_tcp_seq_dup_count", 0) or 0),
            "fwd_tcp_ack_dup_count": int(flow_info.get("fwd_tcp_ack_dup_count", 0) or 0),
            "bwd_tcp_ack_dup_count": int(flow_info.get("bwd_tcp_ack_dup_count", 0) or 0),
            "fwd_synack_count": int(flow_info.get("fwd_synack_count", 0) or 0),
            "bwd_synack_count": int(flow_info.get("bwd_synack_count", 0) or 0),
            "fwd_http_status_count": int(flow_info.get("fwd_http_status_count", 0) or 0),
            "bwd_http_status_count": int(flow_info.get("bwd_http_status_count", 0) or 0),
            "severity": severity,
            "heuristics": heuristics,
            "candidate_block_ip": candidate_ip,
            "model_votes": pred["model_votes"],
            "confidence_score": float((pred.get("model_votes", {}) or {}).get("confidence_score", 0.0)),
            "raw_model_outputs": raw_pred,
            **pred,
        }
        record = to_json_safe(record)

        attack_run = match_attack_run(record)
        if attack_run:
            record["attack_run_id"] = attack_run["id"]
            record["attack_run_label"] = attack_run["attack_label"]
        scored_records.append(record)

    scored_records = correlate_attack_patterns(scored_records)

    for record in scored_records:
        blocked = False
        candidate_ip = record.get("candidate_block_ip")
        if should_auto_block(record) and candidate_ip:
            firewall_result = firewall_block_ip(candidate_ip, f"Auto-blocked for {record.get('rf_labels', 'anomalous traffic')}")
            firewall_result["block_source"] = "auto"
            firewall_result["heal_at"] = compute_heal_at(firewall_result.get("blocked_at"), STATE.healing_window_seconds)
            firewall_result["heal_status"] = "scheduled"
            record["prevention_result"] = firewall_result
            if firewall_result.get("success"):
                blocked = True
                with STATE.lock:
                    STATE.blocked_ips[candidate_ip] = normalize_block_entry(candidate_ip, firewall_result)
        elif candidate_ip and candidate_ip in STATE.blocked_ips:
            record["prevention_result"] = STATE.blocked_ips[candidate_ip]

        if str(record.get("severity", "normal")).lower() in ("high", "medium"):
            src_ip = str((record.get("flow_key", {}) or {}).get("src_ip", "") or "")
            dst_ip = str((record.get("flow_key", {}) or {}).get("dst_ip", "") or "")
            severity = str(record.get("severity", "normal")).lower()
            add_alert(record, f"{severity.upper()} alert", f"{record['rf_labels']} between {src_ip} and {dst_ip}", blocked=blocked)

        attack_run_id = str(record.get("attack_run_id", "") or "")
        if attack_run_id:
            update_attack_run_detection(attack_run_id, record)
    return scored_records


def capture_loop(selected_iface: str) -> None:
    capture_ifaces = build_capture_ifaces(selected_iface)
    print(f"Capture interfaces: {capture_ifaces}")

    try:
        while True:
            with STATE.lock:
                if not STATE.capturing:
                    break

            try:
                maintain_healing()
                packets = capture_packets_with_fallback(capture_ifaces, CAPTURE_PACKET_BATCH, CAPTURE_TIMEOUT_SECONDS)
                rows = feature_rows_from_packets(packets)
                records = score_rows(rows)
                if not records:
                    continue

                append_results(records)
                with STATE.lock:
                    STATE.capture_error = ""
                persist_results()
            except Exception as exc:
                with STATE.lock:
                    STATE.capture_error = str(exc)
                print(f"Capture loop error: {exc}")
                time.sleep(2)
    finally:
        with STATE.lock:
            STATE.capturing = False
            STATE.capture_thread = None


def analysis_snapshot() -> dict:
    maintain_healing()
    with STATE.lock:
        results = list(STATE.results)
        alerts = list(STATE.alerts)
        blocked_ips = dict(STATE.blocked_ips)
        attack_runs = list(STATE.attack_runs)
        pcap_runs = [
            dict(run)
            for run in STATE.attack_runs
            if run.get("run_kind") == "pcap_replay" and int(run.get("replay_version", 0) or 0) == PCAP_REPLAY_VERSION
        ]
        packet_debug = list(STATE.packet_debug)
        capture_stats = dict(STATE.capture_stats)
        healed_events = list(STATE.healed_events)
        healing_enabled = STATE.healing_enabled
        healing_window_seconds = STATE.healing_window_seconds

    healing_queue = [
        {"ip": ip, **metadata}
        for ip, metadata in blocked_ips.items()
        if isinstance(metadata, dict) and is_auto_block_entry(metadata)
    ]

    if not results:
        return {
            "total_flows": 0,
            "risk_distribution": {},
            "rf_classification": {},
            "top_destinations": {},
            "top_sources": {},
            "top_ports": {},
            "protocol_distribution": {},
            "ae_anomalies": {"count": 0, "pct": 0},
            "alerts_count": len(alerts),
            "blocked_count": len(blocked_ips),
            "model_agreement": {"core_models_agree": 0, "pct": 0},
            "model_comparison": {},
            "model_matrix": {},
            "severity_timeline": [],
            "proto_risk_matrix": {},
            "top_talkers": [],
            "feature_highlights": {},
            "capture_stats": capture_stats,
            "packet_debug": packet_debug,
            "attack_runs": attack_runs,
            "pcap_runs": pcap_runs,
            "healing_enabled": healing_enabled,
            "healing_window_seconds": healing_window_seconds,
            "healing_queue": healing_queue,
            "healing_history": healed_events,
        }

    risk_distribution = Counter(r.get("ensemble_risk", "unknown") for r in results)
    rf_labels = Counter(r.get("rf_labels", "BENIGN") for r in results)
    dests = Counter(r["flow_key"]["dst_ip"] for r in results)
    sources = Counter(r["flow_key"]["src_ip"] for r in results)
    ports = Counter(str(r["flow_key"]["dport"]) for r in results)
    protocols = Counter(str(r["flow_key"]["proto"]) for r in results)
    ae_count = sum(1 for r in results if r.get("ae_anomaly"))
    agree_count = sum(
        1
        for r in results
        if str(r.get("rf_labels", "BENIGN")).upper() != "BENIGN"
        and str(r.get("gbdt_labels", "BENIGN")).upper() != "BENIGN"
        and str(r.get("gnn_label", "normal")).lower() == "attack"
    )
    raw_outputs = [r.get("raw_model_outputs", {}) for r in results]
    ae_flags = [bool(o.get("ae_anomaly")) for o in raw_outputs]
    iso_high = [str(o.get("iso_risk", "normal")).lower() == "high" for o in raw_outputs]
    km_high = [str(o.get("kmeans_risk", "normal")).lower() == "high" for o in raw_outputs]
    rf_non_benign = [str(o.get("rf_labels", "BENIGN")).upper() != "BENIGN" for o in raw_outputs]
    gbdt_non_benign = [str(r.get("gbdt_labels", "BENIGN")).upper() != "BENIGN" for r in results]
    ppo_high = [str(r.get("ppo_risk", "normal")).lower() == "high" for r in results]
    gnn_attack = [
        str(r.get("gnn_label", "normal")).lower() == "attack" and float(r.get("gnn_attack_prob", 0) or 0) >= 0.85
        for r in results
    ]
    iso_scores = [float(o.get("iso_score", 0) or 0) for o in raw_outputs if o.get("iso_score") is not None]
    km_scores = [float(o.get("kmeans_score", 0) or 0) for o in raw_outputs if o.get("kmeans_score") is not None]
    ae_scores = [float(o.get("ae_score", 0) or 0) for o in raw_outputs if o.get("ae_score") is not None]
    rf_raw_labels = Counter(str(o.get("rf_labels", "BENIGN")) for o in raw_outputs)
    gbdt_labels = Counter(str(r.get("gbdt_labels", "BENIGN")) for r in results if r.get("gbdt_labels"))
    ppo_labels = Counter(str(r.get("ppo_risk", "normal")) for r in results if r.get("ppo_risk"))
    gnn_labels = Counter(str(r.get("gnn_label", "normal")) for r in results if r.get("gnn_label"))
    severity_timeline = []
    bucketed = {}
    for r in results:
        ts = str(r.get("timestamp", ""))[11:16]
        bucket = bucketed.setdefault(ts, Counter())
        bucket[str(r.get("severity", "normal")).lower()] += 1
    for ts, counter in sorted(bucketed.items()):
        severity_timeline.append({"time": ts, **counter})

    proto_risk_matrix = {}
    for r in results:
        proto = str(r.get("proto_name") or r["flow_key"].get("proto"))
        proto_risk_matrix.setdefault(proto, Counter())
        proto_risk_matrix[proto][str(r.get("severity", "normal")).lower()] += 1

    top_talkers = []
    pair_counts = Counter(
        f"{r['flow_key']['src_ip']}->{r['flow_key']['dst_ip']}:{r['flow_key']['dport']}" for r in results
    )
    for pair, count in pair_counts.most_common(12):
        top_talkers.append({"flow": pair, "count": count})

    feature_highlights = {
        "avg_packets_per_sec": round(float(np.mean([float(r.get("flow_packets/s", 0) or 0) for r in results])), 2),
        "avg_bytes_per_sec": round(float(np.mean([float(r.get("flow_bytes/s", 0) or 0) for r in results])), 2),
        "avg_packet_size": round(float(np.mean([float(r.get("average_packet_size", 0) or 0) for r in results])), 2),
        "syn_burst_flows": int(sum(1 for r in results if int(r.get("syn_flag_count", 0) or 0) >= 20)),
    }

    model_comparison = {
        "autoencoder": {
            "metric_label": "AE anomalies",
            "primary_value": sum(ae_flags),
            "secondary_value": f"{(np.mean(ae_scores) if ae_scores else 0):.4f}",
            "secondary_label": "avg reconstruction score",
            "pct": sum(ae_flags) / len(results) * 100,
        },
        "isolation_forest": {
            "metric_label": "ISO high anomalies",
            "primary_value": sum(iso_high),
            "secondary_value": f"{(np.mean(iso_scores) if iso_scores else 0):.4f}",
            "secondary_label": "avg normalized score",
            "pct": sum(iso_high) / len(results) * 100,
            "high_count": sum(iso_high),
        },
        "kmeans": {
            "metric_label": "KM high anomalies",
            "primary_value": sum(km_high),
            "secondary_value": f"{(np.mean(km_scores) if km_scores else 0):.4f}",
            "secondary_label": "avg normalized score",
            "pct": sum(km_high) / len(results) * 100,
            "high_count": sum(km_high),
        },
        "random_forest": {
            "metric_label": "RF non-benign",
            "primary_value": sum(rf_non_benign),
            "secondary_value": rf_raw_labels.most_common(1)[0][0] if rf_raw_labels else "BENIGN",
            "secondary_label": "top raw label",
            "pct": sum(rf_non_benign) / len(results) * 100,
        },
        "gradient_boosted_tree": {
            "metric_label": "GBDT non-benign",
            "primary_value": sum(gbdt_non_benign),
            "secondary_value": gbdt_labels.most_common(1)[0][0] if gbdt_labels else "BENIGN",
            "secondary_label": "top label",
            "pct": sum(gbdt_non_benign) / len(results) * 100,
        },
        "ppo_policy": {
            "metric_label": "PPO high risk",
            "primary_value": sum(ppo_high),
            "secondary_value": ppo_labels.most_common(1)[0][0] if ppo_labels else "normal",
            "secondary_label": "top risk",
            "pct": sum(ppo_high) / len(results) * 100,
        },
        "gnn_detector": {
            "metric_label": "GNN high-confidence attacks",
            "primary_value": sum(gnn_attack),
            "secondary_value": gnn_labels.most_common(1)[0][0] if gnn_labels else "normal",
            "secondary_label": "top output",
            "pct": sum(gnn_attack) / len(results) * 100,
        },
    }

    model_matrix = {
        "ae": {"flagged": sum(ae_flags), "pct": round(sum(ae_flags) / len(results) * 100, 2), "avg_score": round(float(np.mean(ae_scores)) if ae_scores else 0.0, 4)},
        "iso": {"flagged": sum(iso_high), "pct": round(sum(iso_high) / len(results) * 100, 2), "avg_score": round(float(np.mean(iso_scores)) if iso_scores else 0.0, 4)},
        "kmeans": {"flagged": sum(km_high), "pct": round(sum(km_high) / len(results) * 100, 2), "avg_score": round(float(np.mean(km_scores)) if km_scores else 0.0, 4)},
        "rf": {"flagged": sum(rf_non_benign), "pct": round(sum(rf_non_benign) / len(results) * 100, 2), "top_label": rf_raw_labels.most_common(1)[0][0] if rf_raw_labels else "BENIGN"},
        "gbdt": {"flagged": sum(gbdt_non_benign), "pct": round(sum(gbdt_non_benign) / len(results) * 100, 2), "top_label": gbdt_labels.most_common(1)[0][0] if gbdt_labels else "BENIGN"},
        "ppo": {"flagged": sum(ppo_high), "pct": round(sum(ppo_high) / len(results) * 100, 2), "top_label": ppo_labels.most_common(1)[0][0] if ppo_labels else "normal"},
        "gnn": {"flagged": sum(gnn_attack), "pct": round(sum(gnn_attack) / len(results) * 100, 2), "top_label": gnn_labels.most_common(1)[0][0] if gnn_labels else "normal"},
    }

    return {
        "total_flows": len(results),
        "risk_distribution": dict(risk_distribution),
        "rf_classification": dict(rf_labels),
        "top_destinations": dict(dests.most_common(8)),
        "top_sources": dict(sources.most_common(8)),
        "top_ports": dict(ports.most_common(8)),
        "protocol_distribution": dict(protocols),
        "ae_anomalies": {"count": ae_count, "pct": ae_count / len(results) * 100},
        "alerts_count": len(alerts),
        "blocked_count": len(blocked_ips),
        "model_agreement": {"core_models_agree": agree_count, "pct": agree_count / len(results) * 100},
        "model_comparison": model_comparison,
        "model_matrix": model_matrix,
        "severity_timeline": severity_timeline,
        "proto_risk_matrix": {k: dict(v) for k, v in proto_risk_matrix.items()},
        "top_talkers": top_talkers,
        "feature_highlights": feature_highlights,
        "capture_stats": capture_stats,
        "packet_debug": packet_debug,
        "attack_runs": attack_runs,
        "pcap_runs": pcap_runs,
        "healing_enabled": healing_enabled,
        "healing_window_seconds": healing_window_seconds,
        "healing_queue": healing_queue,
        "healing_history": healed_events,
    }


def pcap_run_snapshot(replay_id: str | None = None, limit: int = 12) -> dict:
    maintain_healing()
    with STATE.lock:
        pcap_runs = [
            dict(run)
            for run in STATE.attack_runs
            if run.get("run_kind") == "pcap_replay" and int(run.get("replay_version", 0) or 0) == PCAP_REPLAY_VERSION
        ]
    if replay_id:
        for run in pcap_runs:
            if run.get("id") == replay_id:
                return {"run": to_json_safe(run), "runs": to_json_safe(pcap_runs[:limit])}
        return {"run": None, "runs": to_json_safe(pcap_runs[:limit])}
    return {"run": to_json_safe(pcap_runs[0]) if pcap_runs else None, "runs": to_json_safe(pcap_runs[:limit])}


@app.route("/")
def root():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/style.css")
def style():
    return send_from_directory(FRONTEND_DIR, "style.css")


@app.route("/script.js")
def script():
    return send_from_directory(FRONTEND_DIR, "script.js")


@app.route("/health")
def health():
    maintain_healing()
    capturing, thread_alive = capture_runtime_state()
    selected_iface_ip = interface_primary_ipv4(STATE.selected_iface)
    recommended_target_ip, recommended_target_iface = preferred_attack_target(STATE.selected_iface)
    with STATE.lock:
        return jsonify(
            {
                "capturing": capturing,
                "capture_thread_alive": thread_alive,
                "selected_iface": STATE.selected_iface,
                "selected_iface_ip": selected_iface_ip,
                "recommended_target_ip": recommended_target_ip,
                "recommended_target_iface": recommended_target_iface,
                "capture_error": STATE.capture_error,
                "models_loaded": MODELS is not None,
                "model_error": MODEL_LOAD_ERROR,
                "prevention_enabled": STATE.prevention_enabled,
                "auto_block_threshold": STATE.auto_block_threshold,
                "healing_enabled": STATE.healing_enabled,
                "healing_window_seconds": STATE.healing_window_seconds,
                "blocked_count": len(STATE.blocked_ips),
                "capture_stats": dict(STATE.capture_stats),
            }
        )


@app.route("/interfaces")
def interfaces():
    recommended_target_ip, recommended_target_iface = preferred_attack_target(STATE.selected_iface)
    return jsonify(
        {
            "interfaces": get_interfaces(),
            "details": interface_inventory(),
            "recommended_target_ip": recommended_target_ip,
            "recommended_target_iface": recommended_target_iface,
        }
    )


@app.route("/attack_catalog")
def attack_catalog():
    return jsonify({"attacks": available_attack_types()})


@app.route("/pcap_catalog")
def pcap_catalog():
    return jsonify({"pcaps": available_pcap_files()})


@app.route("/upload_pcap", methods=["POST"])
def upload_pcap():
    try:
        uploaded = request.files.get("file")
        saved = save_uploaded_pcap(uploaded)
        return jsonify({"status": "uploaded", "pcap": saved, "pcaps": available_pcap_files()})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/status")
def status():
    maintain_healing()
    capturing, thread_alive = capture_runtime_state()
    selected_iface_ip = interface_primary_ipv4(STATE.selected_iface)
    recommended_target_ip, recommended_target_iface = preferred_attack_target(STATE.selected_iface)
    with STATE.lock:
        return jsonify(
            {
                "capturing": capturing,
                "capture_thread_alive": thread_alive,
                "selected_iface": STATE.selected_iface,
                "selected_iface_ip": selected_iface_ip,
                "recommended_target_ip": recommended_target_ip,
                "recommended_target_iface": recommended_target_iface,
                "capture_error": STATE.capture_error,
                "results_count": len(STATE.results),
                "alerts_count": len(STATE.alerts),
                "blocked_count": len(STATE.blocked_ips),
                "prevention_enabled": STATE.prevention_enabled,
                "auto_block_threshold": STATE.auto_block_threshold,
                "healing_enabled": STATE.healing_enabled,
                "healing_window_seconds": STATE.healing_window_seconds,
                "healed_count": len(STATE.healed_events),
                "capture_stats": dict(STATE.capture_stats),
            }
        )


@app.route("/prevention", methods=["GET", "POST"])
def prevention():
    if request.method == "GET":
        maintain_healing()
        with STATE.lock:
            return jsonify({"enabled": STATE.prevention_enabled, "auto_block_threshold": STATE.auto_block_threshold})

    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get("enabled", False))
    threshold = str(payload.get("auto_block_threshold", "high")).lower()
    if threshold not in RISK_RANK:
        return jsonify({"error": "Invalid threshold"}), 400

    removed_auto_blocks: list[str] = []
    with STATE.lock:
        was_enabled = STATE.prevention_enabled
        STATE.prevention_enabled = enabled
        STATE.auto_block_threshold = threshold
    if not enabled and was_enabled:
        removed_auto_blocks = clear_auto_blocks()
    persist_results()
    return jsonify({"enabled": enabled, "auto_block_threshold": threshold, "removed_auto_blocks": removed_auto_blocks})


@app.route("/healing", methods=["GET", "POST"])
def healing():
    if request.method == "GET":
        maintain_healing()
        with STATE.lock:
            return jsonify(
                {
                    "enabled": STATE.healing_enabled,
                    "healing_window_seconds": STATE.healing_window_seconds,
                    "healed_count": len(STATE.healed_events),
                }
            )

    payload = request.get_json(silent=True) or {}
    enabled = bool(payload.get("enabled", True))
    healing_window_seconds = max(30, int(payload.get("healing_window_seconds") or STATE.healing_window_seconds))

    with STATE.lock:
        STATE.healing_enabled = enabled
        STATE.healing_window_seconds = healing_window_seconds
        for ip, metadata in list(STATE.blocked_ips.items()):
            if not isinstance(metadata, dict) or not is_auto_block_entry(metadata):
                continue
            STATE.blocked_ips[ip] = normalize_block_entry(ip, metadata)
            if enabled:
                STATE.blocked_ips[ip]["heal_at"] = compute_heal_at(STATE.blocked_ips[ip].get("blocked_at"), healing_window_seconds)
                STATE.blocked_ips[ip]["heal_status"] = "scheduled"
    persist_results()
    return jsonify({"enabled": enabled, "healing_window_seconds": healing_window_seconds})


@app.route("/start", methods=["POST"])
def start_capture():
    payload = request.get_json(silent=True) or {}
    available = get_interfaces()
    iface = payload.get("iface") or (available[0] if available else "Wi-Fi")

    with STATE.lock:
        if STATE.capturing:
            return jsonify({"error": "Capture already in progress"}), 400
        STATE.capturing = True
        STATE.selected_iface = iface
        STATE.capture_error = ""
        STATE.failed_ifaces.clear()
        STATE.results.clear()
        STATE.alerts.clear()
        STATE.packet_debug.clear()
        STATE.capture_stats.clear()

    STATE.capture_thread = threading.Thread(target=capture_loop, args=(iface,), daemon=True)
    STATE.capture_thread.start()
    persist_results()
    return jsonify({"status": "started", "iface": iface})


@app.route("/stop", methods=["POST"])
def stop_capture():
    with STATE.lock:
        STATE.capturing = False
    return jsonify({"status": "stopped"})


@app.route("/results")
def results():
    limit = int(request.args.get("limit", 100))
    with STATE.lock:
        items = list(STATE.results)[:limit]
    return jsonify({"results": to_json_safe(items)})


@app.route("/alerts")
def alerts():
    with STATE.lock:
        return jsonify({"alerts": to_json_safe(list(STATE.alerts))})


@app.route("/blocked_ips")
def blocked_ips():
    maintain_healing()
    with STATE.lock:
        values = [{"ip": ip, **metadata} for ip, metadata in STATE.blocked_ips.items()]
    return jsonify({"blocked_ips": to_json_safe(values)})


@app.route("/analysis")
def analysis():
    return jsonify(analysis_snapshot())


@app.route("/pcap_status")
def pcap_status():
    replay_id = str(request.args.get("id") or "").strip() or None
    limit = max(1, min(20, int(request.args.get("limit", 12))))
    return jsonify(pcap_run_snapshot(replay_id=replay_id, limit=limit))


@app.route("/clear_results", methods=["POST"])
def clear_results():
    with STATE.lock:
        STATE.results.clear()
        STATE.alerts.clear()
        STATE.packet_debug.clear()
        STATE.capture_stats.clear()
    persist_results()
    return jsonify({"status": "cleared"})


@app.route("/clear_pcap_replays", methods=["POST"])
def clear_pcap_replays():
    removed_runs = 0
    removed_results = 0
    removed_alerts = 0
    with STATE.lock:
        kept_runs = deque(maxlen=STATE.attack_runs.maxlen)
        for run in STATE.attack_runs:
            if run.get("run_kind") == "pcap_replay":
                removed_runs += 1
            else:
                kept_runs.append(run)
        STATE.attack_runs = kept_runs

        kept_results = deque(maxlen=STATE.results.maxlen)
        for record in STATE.results:
            if str(record.get("traffic_source", "") or "").lower() == "pcap_replay" or str(record.get("attack_run_label", "") or "").lower() == "pcap replay":
                removed_results += 1
            else:
                kept_results.append(record)
        STATE.results = kept_results

        kept_alerts = deque(maxlen=STATE.alerts.maxlen)
        for alert in STATE.alerts:
            if str(alert.get("traffic_source", "") or "").lower() == "pcap_replay" or str(alert.get("attack_run_label", "") or "").lower() == "pcap replay":
                removed_alerts += 1
            else:
                kept_alerts.append(alert)
        STATE.alerts = kept_alerts
    persist_results()
    return jsonify({
        "status": "cleared",
        "removed_runs": removed_runs,
        "removed_results": removed_results,
        "removed_alerts": removed_alerts,
    })


@app.route("/block_ip", methods=["POST"])
def block_ip():
    payload = request.get_json(silent=True) or {}
    try:
        ip = normalize_ip(payload.get("ip", ""))
    except Exception:
        return jsonify({"error": "Invalid IP address"}), 400

    reason = payload.get("reason", "Manual block from dashboard")
    result = firewall_block_ip(ip, reason)
    with STATE.lock:
        if result.get("success"):
            result["status"] = "active"
            result["block_source"] = "manual"
            STATE.blocked_ips[ip] = normalize_block_entry(ip, result)
        else:
            # Preserve the operator request in dashboard state so it is visible
            # whether the firewall application succeeded or not.
            STATE.blocked_ips[ip] = normalize_block_entry(ip, {
                **result,
                "status": "failed",
                "block_source": "manual",
                "applied": False,
                "blocked_at": result.get("blocked_at") or now_iso(),
            })
    persist_results()
    return jsonify(result)


@app.route("/unblock_ip", methods=["POST"])
def unblock_ip():
    payload = request.get_json(silent=True) or {}
    try:
        ip = normalize_ip(payload.get("ip", ""))
    except Exception:
        return jsonify({"error": "Invalid IP address"}), 400

    result = firewall_unblock_ip(ip)
    with STATE.lock:
        STATE.blocked_ips.pop(ip, None)
    persist_results()
    return jsonify(result)


@app.route("/heal_ip", methods=["POST"])
def heal_ip():
    payload = request.get_json(silent=True) or {}
    try:
        ip = normalize_ip(payload.get("ip", ""))
    except Exception:
        return jsonify({"error": "Invalid IP address"}), 400

    result = heal_block(ip, trigger="manual_heal")
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/simulate_attack", methods=["POST"])
def simulate_attack_route():
    payload = request.get_json(silent=True) or {}
    try:
        attack_id = f"attack-{int(now_ts() * 1000)}"
        attack_type = payload.get("attack_type", "icmp_flood")
        requested_target_ip = str(payload.get("target_ip") or "").strip()
        requested_iface = str(payload.get("iface") or "").strip()
        auto_target = bool(payload.get("auto_target", False))
        recommended_target_ip, recommended_target_iface = preferred_attack_target(requested_iface)
        send_iface = requested_iface or recommended_target_iface or STATE.selected_iface
        target_ip = requested_target_ip or recommended_target_ip or "127.0.0.1"
        if auto_target or not requested_target_ip:
            target_ip = recommended_target_ip or target_ip
        target_port = int(payload.get("target_port") or 0) or None
        start_port = int(payload.get("start_port") or 0) or None
        packet_count = int(payload.get("packet_count") or 0) or None
        payload_size = int(payload.get("payload_size") or 0) or None
        interval = float(payload.get("interval") or 0) or None
        started_ts = now_ts()
        source_ip = interface_primary_ipv4(send_iface)
        simulation = simulate_attack(
            attack_type=attack_type,
            target_ip=target_ip,
            packet_count=packet_count,
            target_port=target_port,
            start_port=start_port,
            payload_size=payload_size,
            interval=interval,
            iface=resolve_capture_iface(send_iface),
            source_ip=source_ip or None,
        )
        sent_packets = list(simulation.pop("_packets", []) or [])
        simulation["id"] = attack_id
        simulation["started_ts"] = started_ts
        simulation["finished_ts"] = started_ts + simulation["duration_seconds"]
        simulation["first_detection_ts"] = None
        simulation["detection_latency_ms"] = None
        simulation["first_prevention_ts"] = None
        simulation["prevention_latency_ms"] = None
        simulation["detection_count"] = 0
        simulation["matched_flows"] = 0
        simulation["blocked_ip"] = None
        simulation["first_detected_label"] = None
        simulation["requested_target_ip"] = requested_target_ip or None
        simulation["target_iface"] = send_iface
        simulation["target_source"] = "selected_interface" if (auto_target or not requested_target_ip) else "manual"
        with STATE.lock:
            STATE.attack_runs.appendleft(simulation)
        if sent_packets:
            injected_rows = feature_rows_from_packets(sent_packets)
            injected_records = score_rows(injected_rows)
            append_results(injected_records)
        persist_results()
        return jsonify({"status": "sent", **simulation})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/replay_pcap", methods=["POST"])
def replay_pcap_route():
    payload = request.get_json(silent=True) or {}
    try:
        pcap_name = str(payload.get("pcap_name") or "").strip()
        requested_iface = str(payload.get("iface") or "").strip()
        packet_limit = int(payload.get("packet_limit") or 0) or None
        loop_count = int(payload.get("loop_count") or 0) or 1
        packets_per_second = float(payload.get("packets_per_second") or 0) or None
        send_packets = bool(payload.get("send_packets", False))
        replay_id = f"pcap-{int(now_ts() * 1000)}"
        started_ts = now_ts()

        replay_run = {
            "id": replay_id,
            "run_kind": "pcap_replay",
            "replay_version": PCAP_REPLAY_VERSION,
            "attack_type": "pcap_replay",
            "attack_label": "PCAP Replay",
            "pcap_name": pcap_name,
            **pcap_profile_info(pcap_name),
            "target_ip": None,
            "target_port": None,
            "proto": None,
            "started_ts": started_ts,
            "finished_ts": None,
            "first_detection_ts": None,
            "detection_latency_ms": None,
            "first_prevention_ts": None,
            "prevention_latency_ms": None,
            "detection_count": 0,
            "matched_flows": 0,
            "attack_candidate_flows": 0,
            "suspicious_pair_count": 0,
            "elevated_pair_count": 0,
            "total_pair_count": 0,
            "total_flow_count": 0,
            "packet_count": 0,
            "loop_count": loop_count,
            "packets_per_second": packets_per_second,
            "packet_limit": packet_limit,
            "blocked_ip": None,
            "first_detected_label": None,
            "target_iface": requested_iface or STATE.selected_iface,
            "replay_status": "running",
            "replay_error": None,
            "replay_mode": "wire" if send_packets else "analysis_only",
            "detection_rate_pct": 0.0,
            "elevated_detection_rate_pct": 0.0,
            "elevated_pair_rate_pct": 0.0,
            "total_pair_elevated_rate_pct": 0.0,
            "suspicious_pair_rate_pct": 0.0,
        }
        with STATE.lock:
            STATE.attack_runs.appendleft(replay_run)
        worker = threading.Thread(
            target=process_pcap_replay_async,
            args=(replay_id, pcap_name, requested_iface, packet_limit, loop_count, packets_per_second, send_packets, started_ts),
            daemon=True,
        )
        worker.start()
        persist_results()
        return jsonify({
            "status": "queued",
            "replay_id": replay_id,
            "replay_run_id": replay_id,
            "pcap_name": pcap_name,
            "iface": requested_iface or STATE.selected_iface,
            "packet_limit": packet_limit,
            "loop_count": loop_count,
            "packets_per_second": packets_per_second,
            "send_packets": send_packets,
            "replay_status": "running",
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/export_csv")
def export_csv():
    with STATE.lock:
        export_rows = list(STATE.results)

    filter_name = request.args.get("filter", "all")
    if filter_name == "high":
        export_rows = [row for row in export_rows if row.get("severity") == "high"]
    elif filter_name == "alerts":
        export_rows = [row for row in export_rows if row.get("severity") in ("high", "medium") or row.get("ae_anomaly")]

    if not export_rows:
        return jsonify({"error": "No rows available for export"}), 400

    pd.DataFrame([flatten_result(row) for row in export_rows]).to_csv(EXPORT_FILE, index=False)
    return send_from_directory(EXPORT_FILE.parent, EXPORT_FILE.name, as_attachment=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug_enabled = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=port, debug=debug_enabled, use_reloader=False)
