@echo off
setlocal
cd /d "%~dp0\.."

if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto :error
)
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
if errorlevel 1 goto :error
python -m pip install -e ".[desktop]"
if errorlevel 1 goto :error
python -m pip install "pyinstaller>=6.10"
if errorlevel 1 goto :error

python -m PyInstaller --noconfirm --clean --windowed --onedir --name Reforge --collect-all PySide6 --hidden-import shiboken6 run_desktop.py
if errorlevel 1 goto :error

echo Portable build created in dist\Reforge\
pause
exit /b 0

:error
echo Portable build failed. Review the output above.
pause
exit /b 1
