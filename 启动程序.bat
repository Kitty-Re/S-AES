@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m saes_app
) else (
    python -m saes_app
)
if errorlevel 1 pause
