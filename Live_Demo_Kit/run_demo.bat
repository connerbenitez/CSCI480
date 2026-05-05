@echo off
echo ============================================================
echo CSCI480 LAYERED IDS/IPS - AUTO DEMO LAUNCHER
echo ============================================================
echo.

cd /d C:\Users\pompk\Desktop\CSCI480

echo [1/5] Checking dependencies...
if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    echo [OK] Nmap installed
) else (
    echo [WARN] Nmap not found - please install from downloads\nmap-setup.exe
)

if exist "C:\Program Files\Colasoft Capsa 11 Free Edition\Capsa.exe" (
    echo [OK] Capsa installed
) else (
    echo [WARN] Capsa not found - please install from downloads\packet_builder.exe
)

echo.
echo [2/5] Starting IDS/IPS System...
start "IDS/IPS Dashboard" cmd /k python run_project.py
echo [INFO] Dashboard opening at http://127.0.0.1:5000
echo [INFO] Wait 10 seconds for dashboard to fully load...
timeout /t 10 /nobreak

echo.
echo [3/5] Launching Nmap (continuous scan loop)...
if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    start "Nmap" cmd /k "cd /d C:\Users\pompk\Desktop\CSCI480\Live_Demo_Kit && nmap_continuous_scan.bat"
    echo [INFO] Nmap continuously scanning localhost (127.0.0.1)
    echo [INFO] Scans every 5 seconds - press Ctrl+C in Nmap window to stop
) else (
    echo [ERROR] Nmap not installed - skipping
)

echo.
echo [4/4] Demo Setup Complete!
echo ============================================================
echo.
echo DEMO TOOLS READY:
echo - IDS/IPS Dashboard: http://127.0.0.1:5000
if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
    echo - Nmap: Scanning localhost (watch for detection)
)
echo.
echo INSTRUCTIONS:
echo 1. In dashboard: Start capture on network interface
echo 2. Watch Nmap scan results appear in dashboard
echo 3. Show Model Settings - 7 ML models
echo 4. Show Defense & Prevention - decoys and firewall
echo 5. Deploy a decoy (fake_ssh)
echo 6. Stop capture
echo.
echo Press any key to close this window (tools remain open)...
pause >nul
