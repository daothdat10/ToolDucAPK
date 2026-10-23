@echo off
setlocal
set "PYTHONUTF8=1"
cd /d "%~dp0"
if not exist "C:\Users\XGame\AppData\Local\Programs\Python\Python312\pythonw.exe" (
  echo Khong tim thay Python 3.12 tai duong dan da cai.
  pause
  exit /b 1
)
start "" "C:\Users\XGame\AppData\Local\Programs\Python\Python312\pythonw.exe" "%~dp0app.py"
