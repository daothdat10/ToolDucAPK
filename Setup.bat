@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\setup.ps1" %*
if errorlevel 1 (
  echo.
  echo Cai dat that bai. Xem thong bao loi o tren, sau do chay lai Setup.bat.
  pause
  exit /b 1
)
echo.
echo Cai dat hoan tat. Mo DucAPK.bat de su dung.
exit /b 0
