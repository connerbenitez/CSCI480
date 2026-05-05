@echo off
cd /d "C:\Program Files (x86)\Nmap"
echo Continuous scan loop - press Ctrl+C to stop
:loop
nmap -sS 127.0.0.1
echo Waiting 5 seconds...
timeout /t 5 /nobreak
goto loop
