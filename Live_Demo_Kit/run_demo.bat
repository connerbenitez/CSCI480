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
echo [3/3] Demo Setup Complete!
echo ============================================================
echo.
echo DEMO TOOLS READY:
echo - IDS/IPS Dashboard: http://127.0.0.1:5000
echo - PreReplay Installer: Live_Demo_Kit\downloads\preplay.exe (run to install)
echo - PCAP Files: port_scan.pcap, syn_flood.pcap, udp_flood.pcap, http_flood.pcap, mixed_attack.pcap
echo.
echo INSTRUCTIONS:
echo 1. In dashboard: Start capture on network interface
echo 2. Show Model Settings - 7 ML models
echo 3. Show Defense & Prevention - decoys and firewall
echo 4. Deploy a decoy (fake_ssh)
echo 5. Run preplay.exe to install PreReplay
echo 6. In PreReplay: File > Open > Select .pcap file > Click Replay
echo 7. Watch dashboard detect the attacks
echo 8. Stop capture
echo.
echo Press any key to close this window (tools remain open)...
pause >nul
