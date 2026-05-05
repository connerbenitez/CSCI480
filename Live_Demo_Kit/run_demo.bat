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
echo [2/5] Starting IDS/IPS System...
start "IDS/IPS Dashboard" cmd /k python run_project.py
echo [INFO] Dashboard opening at http://127.0.0.1:5000
echo [INFO] Wait 10 seconds for dashboard to fully load...
timeout /t 10 /nobreak

echo.
echo [3/4] Launching Capsa...
if exist "C:\Program Files\Colasoft Capsa 11 Free Edition\Capsa.exe" (
    start "Capsa" "C:\Program Files\Colasoft Capsa 11 Free Edition\Capsa.exe"
    echo [INFO] Capsa opened
    echo [IMPORTANT] In Capsa: Select WiFi interface (NOT Ethernet)
) else (
    echo [ERROR] Capsa not installed - skipping
)

echo.
echo [4/4] Demo Setup Complete!
echo ============================================================
echo.
echo DEMO TOOLS READY:
echo - IDS/IPS Dashboard: http://127.0.0.1:5000
if exist "C:\Program Files\Colasoft Capsa 11 Free Edition\Capsa.exe" (
    echo - Capsa: Open for manual packet generation
)
echo - Nmap shortcut: Double-click to run scan when needed
echo.
echo INSTRUCTIONS:
echo 1. In dashboard: Start capture on network interface
echo 2. Show Model Settings - 7 ML models
echo 3. Show Defense & Prevention - decoys and firewall
echo 4. Deploy a decoy (fake_ssh)
echo 5. Double-click Nmap shortcut to run port scan
echo 6. Watch dashboard detect the scan
echo 7. Use Capsa manually to generate custom traffic if needed
echo 8. Stop capture
echo.
echo Press any key to close this window (tools remain open)...
pause >nul
