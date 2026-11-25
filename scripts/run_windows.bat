@echo off
setlocal
cd /d "%~dp0\.."
if not exist ".venv\Scripts\activate.bat" (
    echo Reforge is not installed. Run scripts\install_windows.bat first.
    pause
    exit /b 1
)
call ".venv\Scripts\activate.bat"
unirep desktop
if errorlevel 1 (
    echo Reforge exited with an error.
    pause
)
