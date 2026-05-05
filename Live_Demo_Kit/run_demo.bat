@echo off
echo ============================================================
echo CSCI480 LAYERED IDS/IPS - AUTO DEMO LAUNCHER
echo ============================================================
echo.

cd /d C:\Users\pompk\Desktop\CSCI480

echo [1/4] Starting IDS/IPS System...
start "IDS/IPS Dashboard" cmd /k python run_project.py
echo [INFO] Dashboard opening at http://127.0.0.1:5000
echo [INFO] Wait 10 seconds for dashboard to fully load...
timeout /t 10 /nobreak

echo.
echo [2/4] Launching Nmap (pre-configured for localhost scan)...
start "Nmap" "C:\Program Files (x86)\Nmap\nmap.exe" -sS 127.0.0.1
echo [INFO] Nmap scanning localhost (127.0.0.1)
echo [INFO] This will demonstrate port scan detection

echo.
echo [3/4] Launching Capsa Packet Builder...
start "Capsa" "C:\Program Files\Colasoft Capsa 11 Free Edition\pktbuilder.exe"
echo [INFO] Capsa Packet Builder opened
echo [INFO] Use this to generate custom attack traffic

echo.
echo [4/4] Demo Setup Complete!
echo ============================================================
echo.
echo DEMO TOOLS READY:
echo - IDS/IPS Dashboard: http://127.0.0.1:5000
echo - Nmap: Scanning localhost (watch for detection)
echo - Capsa: Packet Builder ready
echo.
echo INSTRUCTIONS:
echo 1. In dashboard: Start capture on network interface
echo 2. Watch Nmap scan results appear in dashboard
echo 3. Use Capsa to generate additional traffic if needed
echo.
echo Press any key to close this window (tools remain open)...
pause >nul
