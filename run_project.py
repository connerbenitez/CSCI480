from __future__ import annotations

import ctypes
import importlib.util
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "Backend"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


def has_module(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if os.name != "nt" or is_admin():
        return False
    try:
        params = " ".join(f'"{arg}"' for arg in sys.argv)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, str(ROOT), 1)
        return True
    except Exception as exc:
        print(f"Warning: could not relaunch as Administrator: {exc}")
        return False


def open_dashboard(delay_seconds: float = 1.3) -> None:
    def _worker():
        time.sleep(delay_seconds)
        try:
            webbrowser.open("http://127.0.0.1:5000")
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


def main() -> int:
    if relaunch_as_admin():
        return 0

    missing = [name for name in ("flask", "flask_cors", "numpy", "pandas", "psutil", "scapy", "torch", "sklearn") if not has_module(name)]
    if missing:
        print("Missing Python packages:", ", ".join(missing))
        print("Install them first from the project root with:")
        print(r"  .\.venv\Scripts\Activate.ps1")
        print(r"  cd .\Backend")
        print(r"  pip install -r requirements.txt")
        return 1

    from Backend.app import app

    print("Launching CSCI480 IDS/IPS dashboard...")
    print("Dashboard will be available at http://127.0.0.1:5000")
    if is_admin():
        print("Administrator privileges detected: prevention and healing firewall actions are available.")
    else:
        print("Running without Administrator privileges: detection works, but firewall prevention actions may fail.")

    open_dashboard()
    port = int(os.environ.get("PORT", "5000"))
    debug_enabled = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=port, debug=debug_enabled, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
