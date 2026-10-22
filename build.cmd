@echo off
rem Double-click entry point. The build lives in build.py - this only starts it
rem from the right directory and keeps the window open afterwards, which a
rem double-clicked script otherwise closes before anyone has read the result.
rem The pause only happens when nobody gave arguments, because a scripted call
rem should not sit waiting for a key.

cd /d "%~dp0"
python build.py %*
set RC=%ERRORLEVEL%

if "%~1"=="" (
    echo.
    pause
)
exit /b %RC%
