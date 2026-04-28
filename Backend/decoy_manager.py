from __future__ import annotations

import socketserver
import threading
import time
from collections import deque
from datetime import UTC, datetime
from typing import Callable


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _to_preview(data: bytes, limit: int = 96) -> str:
    if not data:
        return ""
    preview = data[:limit].decode("utf-8", errors="replace")
    return "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in preview).strip()


DECOY_LIBRARY: dict[str, dict] = {
    "fake_ssh": {
        "label": "Fake SSH",
        "description": "Low-interaction SSH banner and prompt decoy.",
        "port": 2222,
        "response_kind": "ssh",
        "default_reason": "Suspicious access against admin-style ports.",
    },
    "fake_http_admin": {
        "label": "Fake HTTP Admin",
        "description": "Minimal web admin login decoy.",
        "port": 8088,
        "response_kind": "http",
        "default_reason": "Suspicious web probing or admin panel discovery.",
    },
    "fake_database": {
        "label": "Fake Database",
        "description": "Minimal generic database listener decoy.",
        "port": 33060,
        "response_kind": "database",
        "default_reason": "Suspicious database service probing.",
    },
    "fake_modbus": {
        "label": "Fake Modbus",
        "description": "Minimal industrial protocol-style decoy listener.",
        "port": 15020,
        "response_kind": "industrial",
        "default_reason": "Suspicious industrial control service probing.",
    },
}


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _DecoyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        self.request.settimeout(2.0)
        data = b""
        try:
            data = self.request.recv(512)
        except Exception:
            data = b""

        event = {
            "timestamp": now_iso(),
            "profile_id": server.profile_id,
            "label": server.profile_label,
            "listener_host": server.listener_host,
            "listener_port": server.listener_port,
            "source_ip": str(self.client_address[0]),
            "source_port": int(self.client_address[1]),
            "payload_preview": _to_preview(data),
            "payload_size": len(data),
            "auto_deployed": bool(server.auto_deployed),
            "reason": server.reason,
        }
        server.event_callback(event)

        try:
            response = _response_bytes(server.response_kind)
            if response:
                self.request.sendall(response)
        except Exception:
            return


def _response_bytes(response_kind: str) -> bytes:
    kind = str(response_kind or "").lower()
    if kind == "ssh":
        return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\nlogin as: "
    if kind == "http":
        body = (
            "<html><head><title>Admin Console</title></head>"
            "<body><h1>Admin Console</h1><p>Authentication required.</p></body></html>"
        )
        header = (
            "HTTP/1.1 401 Unauthorized\r\n"
            "Server: nginx\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
        )
        return header.encode("utf-8") + body.encode("utf-8")
    if kind == "database":
        return b"5.7.0-mockdb\x00Access denied for user\r\n"
    if kind == "industrial":
        return b"MBAP\x00\x00\x00\x06\x01\x11\x01\x00"
    return b""


class DecoyManager:
    def __init__(self, event_callback: Callable[[dict], None] | None = None, max_events: int = 200) -> None:
        self._lock = threading.RLock()
        self._active: dict[str, dict] = {}
        self._events: deque[dict] = deque(maxlen=max_events)
        self._event_callback = event_callback

    def available_profiles(self) -> dict[str, dict]:
        return {key: dict(value) for key, value in DECOY_LIBRARY.items()}

    def list_active_decoys(self) -> list[dict]:
        with self._lock:
            return [self._public_decoy_payload(item) for item in self._active.values()]

    def recent_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return [dict(item) for item in list(self._events)[: max(1, int(limit))]]

    def count_recent_events_for_source(self, source_ip: str, within_seconds: int = 900) -> int:
        if not source_ip:
            return 0
        now = time.time()
        count = 0
        with self._lock:
            for item in self._events:
                if str(item.get("source_ip", "") or "") != str(source_ip):
                    continue
                ts = item.get("timestamp")
                if ts:
                    try:
                        event_ts = datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
                    except Exception:
                        event_ts = now
                else:
                    event_ts = now
                if event_ts >= now - max(30, int(within_seconds)):
                    count += 1
        return count

    def deploy_decoy(
        self,
        profile_id: str,
        reason: str | None = None,
        source_ip: str | None = None,
        auto_deployed: bool = False,
    ) -> dict:
        profile_key = str(profile_id or "").strip().lower()
        profile = DECOY_LIBRARY.get(profile_key)
        if not profile:
            return {"success": False, "message": f"Unknown decoy profile '{profile_id}'."}

        with self._lock:
            existing = self._active.get(profile_key)
            if existing:
                if source_ip and source_ip not in existing["source_ips"]:
                    existing["source_ips"].append(source_ip)
                existing["last_requested_at"] = now_iso()
                if reason:
                    existing["reason"] = reason
                return {
                    "success": True,
                    "already_active": True,
                    "message": f"{profile['label']} is already active.",
                    "decoy": self._public_decoy_payload(existing),
                }

        listener_host = "0.0.0.0"
        listener_port = int(profile["port"])
        reason_text = reason or str(profile.get("default_reason", "") or "Operator deployment")
        server = None
        try:
            server = _ThreadedTCPServer((listener_host, listener_port), _DecoyHandler)
            server.profile_id = profile_key
            server.profile_label = str(profile["label"])
            server.listener_host = listener_host
            server.listener_port = listener_port
            server.response_kind = str(profile.get("response_kind", ""))
            server.reason = reason_text
            server.auto_deployed = bool(auto_deployed)
            server.event_callback = self._record_event
            thread = threading.Thread(target=server.serve_forever, daemon=True, name=f"decoy-{profile_key}")
            thread.start()
        except OSError as exc:
            if server is not None:
                try:
                    server.server_close()
                except Exception:
                    pass
            return {
                "success": False,
                "message": f"Failed to bind {profile['label']} on port {listener_port}: {exc}",
            }

        metadata = {
            "profile_id": profile_key,
            "label": str(profile["label"]),
            "description": str(profile.get("description", "")),
            "listener_host": listener_host,
            "listener_port": listener_port,
            "response_kind": str(profile.get("response_kind", "")),
            "reason": reason_text,
            "auto_deployed": bool(auto_deployed),
            "source_ips": [source_ip] if source_ip else [],
            "deployed_at": now_iso(),
            "last_requested_at": now_iso(),
            "last_event_at": None,
            "event_count": 0,
            "_server": server,
            "_thread": thread,
        }
        with self._lock:
            self._active[profile_key] = metadata

        return {
            "success": True,
            "message": f"{profile['label']} deployed on port {listener_port}.",
            "decoy": self._public_decoy_payload(metadata),
        }

    def remove_decoy(self, profile_id: str) -> dict:
        profile_key = str(profile_id or "").strip().lower()
        with self._lock:
            metadata = self._active.pop(profile_key, None)
        if not metadata:
            return {"success": False, "message": f"No active decoy found for '{profile_id}'."}

        server = metadata.get("_server")
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass

        return {
            "success": True,
            "message": f"{metadata['label']} removed.",
            "decoy": self._public_decoy_payload(metadata),
        }

    def stop_all(self) -> None:
        with self._lock:
            profile_ids = list(self._active.keys())
        for profile_id in profile_ids:
            self.remove_decoy(profile_id)

    def _record_event(self, event: dict) -> None:
        callback = self._event_callback
        with self._lock:
            self._events.appendleft(dict(event))
            metadata = self._active.get(str(event.get("profile_id", "") or ""))
            if metadata:
                metadata["event_count"] = int(metadata.get("event_count", 0) or 0) + 1
                metadata["last_event_at"] = event.get("timestamp")
                source_ip = str(event.get("source_ip", "") or "")
                if source_ip and source_ip not in metadata["source_ips"]:
                    metadata["source_ips"].append(source_ip)
        if callback is not None:
            try:
                callback(dict(event))
            except Exception:
                return

    def _public_decoy_payload(self, metadata: dict) -> dict:
        return {
            "profile_id": metadata.get("profile_id"),
            "label": metadata.get("label"),
            "description": metadata.get("description"),
            "listener_host": metadata.get("listener_host"),
            "listener_port": metadata.get("listener_port"),
            "response_kind": metadata.get("response_kind"),
            "reason": metadata.get("reason"),
            "auto_deployed": bool(metadata.get("auto_deployed")),
            "source_ips": list(metadata.get("source_ips", [])),
            "deployed_at": metadata.get("deployed_at"),
            "last_requested_at": metadata.get("last_requested_at"),
            "last_event_at": metadata.get("last_event_at"),
            "event_count": int(metadata.get("event_count", 0) or 0),
        }
