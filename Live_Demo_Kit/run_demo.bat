@echo off
echo ============================================================
echo CSCI480 LAYERED IDS/IPS - AUTO DEMO LAUNCHER
echo ============================================================
echo.

cd /d C:\Users\pompk\Desktop\CSCI480
echo.
echo [1/5] Checking dependencies...
if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    echo [OK] Nmap installed
) else (
    echo [WARN] Nmap not found - installing Zenmap...
    if exist "Live_Demo_Kit\downloads\zenmap-setup.exe" (
        start /wait "" "Live_Demo_Kit\downloads\zenmap-setup.exe"
        echo [INFO] Zenmap installation complete
    ) else (
        echo [ERROR] Zenmap installer not found
    )
)

if exist "C:\Program Files\Colasoft Capsa 11 Free Edition\Capsa.exe" (
    echo [OK] Capsa installed
) else (
    echo [WARN] Capsa not found - please install from downloads\packet_builder.exe
)

echo.
echo [2/3] Starting IDS/IPS System...
start "IDS/IPS Dashboard" cmd /k python run_project.py
echo [INFO] Dashboard opening at http://127.0.0.1:5000
echo [INFO] Wait 10 seconds for dashboard to fully load...
timeout /t 10 /nobreak

echo.
echo [3/3] Launching PCAP Replay GUI Tool...
cd /d Live_Demo_Kit
start "PCAP Replay GUI" python replay_pcap_gui.py
cd /d C:\Users\pompk\Desktop\CSCI480
echo [INFO] PCAP Replay GUI opened

echo.
echo [3/3] Demo Setup Complete!
echo ============================================================
echo.
echo DEMO TOOLS READY:
echo - IDS/IPS Dashboard: http://127.0.0.1:5000
echo - PCAP Replay GUI: Free GUI tool for replaying PCAP files
echo - PCAP Files: port_scan.pcap, syn_flood.pcap, udp_flood.pcap, http_flood.pcap, mixed_attack.pcap
echo.
echo INSTRUCTIONS:
echo 1. In dashboard: Start capture on network interface
echo 2. Show Model Settings - 7 ML models
echo 3. Show Defense & Prevention - decoys and firewall
echo 4. Deploy a decoy (fake_ssh)
echo 5. In PCAP Replay GUI: Select PCAP file from list or browse
echo 6. Click "Replay PCAP" to send packets
echo 7. Watch dashboard detect the attacks
echo 8. Stop capture
echo.
echo Press any key to close this window (tools remain open)...
pause >nul
