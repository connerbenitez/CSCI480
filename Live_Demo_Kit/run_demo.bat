@echo off
REM CSCI480 Layered IDS/IPS - Live Demo Launcher
REM Senior Capstone Project (Academic Demonstration)
REM Team: Joshua Swanson | Jerry Buno | Conner Benitez

echo ===============================================================================
echo CSCI480 LAYERED IDS/IPS - LIVE DEMO LAUNCHER
echo ===============================================================================
echo Senior Capstone Project (Academic Demonstration)
echo Team: Joshua Swanson | Jerry Buno | Conner Benitez
echo ===============================================================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges - Prevention/Healing enabled
) else (
    echo [WARNING] Not running as Administrator - Detection works, but prevention may fail
    echo For full functionality, right-click and "Run as Administrator"
)
echo.

REM Check Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.11 or higher
    pause
    exit /b 1
)

echo [1/2] Navigating to project directory...
cd /d "%~dp0.."
if %errorLevel% neq 0 (
    echo [ERROR] Could not navigate to project directory
    pause
    exit /b 1
)

echo [2/2] Starting the application...
echo.
echo ===============================================================================
echo DASHBOARD WILL OPEN IN YOUR DEFAULT BROWSER
echo URL: http://127.0.0.1:5000
echo ===============================================================================
echo.
echo Press Ctrl+C to stop the server
echo.

python run_project.py

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Application failed to start
    echo Check the error message above for details
)

pause
