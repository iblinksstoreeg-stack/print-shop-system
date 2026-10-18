@echo off
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Download the LTS version from https://nodejs.org then run this file again.
  pause
  exit /b
)
if not exist ".env" copy ".env.example" ".env" >nul
echo Starting... the system will open in your browser at http://localhost:3000
start "" http://localhost:3000
node server.js
pause
