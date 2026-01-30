@echo off
echo 🤖 DOX - Basic Setup
echo ====================

:: Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not found. Please install Python 3.10+
    pause
    exit /b 1
)

:: Run the complete setup
python setup.py

pause