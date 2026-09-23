@echo off
setlocal
title PS-8 Security Monitoring Platform

echo ================================================================
echo    Starting PS-8 Security Platform
echo ================================================================
echo.

:: Check if Python is available
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python is not found in your system PATH.
    echo Please install Python 3.10 or newer from https://www.python.org/
    echo and make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

:: Run the unified python runner
python run.py

if %ERRORLEVEL% neq 0 (
    echo.
    echo [INFO] Process ended with error code %ERRORLEVEL%.
    pause
)
