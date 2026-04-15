# Live IDS / IPS Testing Guide

## Browser Workflow

1. Open an elevated terminal in `C:\Users\pompk\Desktop\CSCI480\Backend`.
2. Install dependencies if needed:

```powershell
pip install -r requirements.txt
```

3. Start the dashboard:

```powershell
python app.py
```

4. Open [http://127.0.0.1:5000](http://127.0.0.1:5000).
5. Choose the active network interface and start capture.
6. Use the `Real Attack Tests` panel to launch `ICMP Flood`, `SYN Flood`, `UDP Flood`, or `Port Scan`.
7. Turn on `Enable automatic blocking` if you want the IPS layer to attempt real firewall blocks.

## CLI Workflow

Use the CLI harness to capture traffic and optionally launch a real attack during the capture window:

```powershell
python test_live_network.py --interface "Wi-Fi" --duration 30 --generate-attack syn_flood --target-ip 127.0.0.1 --target-port 80 --attack-count 40 --output syn_test.csv
```

Supported attack names:

- `icmp_flood`
- `syn_flood`
- `udp_flood`
- `port_scan`

## What Is Real vs Simulated

- Packet capture uses Scapy sniffing on the selected interface.
- Attack tests send real packets using Scapy.
- Prevention uses real firewall commands:
  - Windows: `netsh advfirewall`
  - Linux: `iptables`

## Important Notes

- Raw capture and packet injection typically require Administrator privileges on Windows.
- Firewall blocking also requires Administrator privileges.
- For safe demos, use loopback or a lab machine you control.
- The dashboard refuses to block loopback or the host's own IP addresses.


cd C:\Users\pompk\Desktop\CSCI480
.\.venv\Scripts\Activate.ps1
python .\run_project.py
