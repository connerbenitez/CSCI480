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

echo [1/4] Checking Python dependencies...
cd /d "%~dp0.."
cd Backend
if not exist "venv_new" (
    echo [INFO] Virtual environment not found, creating...
    python -m venv venv_new
)

echo [2/4] Activating virtual environment...
call venv_new\Scripts\activate.bat

echo [3/4] Installing dependencies (if needed)...
pip install -q -r requirements.txt 2>nul

echo [4/4] Starting the application...
echo.
echo ===============================================================================
echo DASHBOARD WILL OPEN IN YOUR DEFAULT BROWSER
echo URL: http://127.0.0.1:5000
echo ===============================================================================
echo.
echo Press Ctrl+C to stop the server
echo.

cd /d "%~dp0.."
python run_project.py

pause
