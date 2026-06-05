@echo off
cd /d "%~dp0"

:: Build MultiWAN QoS Agent as a single .exe
echo.
echo  =============================================
echo   MultiWAN QoS Agent - Build
echo  =============================================
echo.

echo [1/2] Installing build dependencies...
python -m pip install pyinstaller psutil requests pystray Pillow pywin32 --quiet
if %errorLevel% neq 0 (
    echo ERROR: Failed to install dependencies.
    if not "%CI%"=="1" pause
    exit /b 1
)

echo [2/2] Building executable...
python -m PyInstaller --onefile --windowed ^
    --name "MultiWAN QoS Agent" ^
    --add-data "multiwan_qos_agent\games_db.json;multiwan_qos_agent" ^
    --uac-admin ^
    --icon NONE ^
    run_agent.py

if %errorLevel% neq 0 (
    echo.
    echo ERROR: Build failed.
    if not "%CI%"=="1" pause
    exit /b 1
)

echo.
echo  Build complete: dist\MultiWAN QoS Agent.exe
echo.
if not "%CI%"=="1" pause
