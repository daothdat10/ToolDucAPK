@echo off
setlocal
set "PYTHONUTF8=1"
set "PYTHONNOUSERSITE=1"
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo Can cai dat runtime truoc khi mo DucAPK.
  call "%~dp0Setup.bat"
  if errorlevel 1 exit /b 1
)
start "" "%~dp0.venv\Scripts\pythonw.exe" "%~dp0app.py"
