@echo off
setlocal
cd /d "%~dp0\.."

echo [Reforge] Creating Python environment...
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto :error
)

call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
if errorlevel 1 goto :error
python -m pip install -e ".[desktop]"
if errorlevel 1 goto :error

echo.
echo Reforge desktop environment is ready.
echo Run scripts\run_windows.bat to launch the application.
pause
exit /b 0

:error
echo.
echo Installation failed. Check that Python 3.10+ is installed and available on PATH.
pause
exit /b 1
