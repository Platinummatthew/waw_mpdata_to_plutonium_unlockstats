@echo off
setlocal EnableExtensions EnableDelayedExpansion
title WaW MPData to Plutonium unlockstats_mp
cd /d "%~dp0"

echo.
echo WaW MPData to Plutonium unlockstats_mp
echo ---------------------------------------
echo Converts retail World at War MPData into the 8192-byte import template
echo used at t4\plutonium\unlockstats_mp.
echo.

if "%~1"=="" (
  echo Drag mpdata, mpdatabk0000, a .corrupt copy, a profile folder, or a ZIP
  echo onto this BAT file, or enter its full path below.
  set /p "INPUT=Source: "
  set "INPUT=!INPUT:"=!"
) else (
  set "INPUT=%~f1"
)

if not exist "!INPUT!" (
  echo.
  echo ERROR: The source was not found:
  echo !INPUT!
  echo.
  pause
  exit /b 2
)

where py >nul 2>&1
if not errorlevel 1 (
  set "PYMODE=py"
) else (
  where python >nul 2>&1
  if not errorlevel 1 set "PYMODE=python"
)

if not defined PYMODE (
  echo.
  echo ERROR: Python 3 was not found.
  echo Open waw_mpdata_to_unlockstats_mp.html instead; it needs no installation.
  echo.
  pause
  exit /b 2
)

if exist "!INPUT!\NUL" (
  set "OUTPUT=!INPUT!\unlockstats_mp"
) else (
  for %%I in ("!INPUT!") do set "OUTPUT=%%~dpIunlockstats_mp"
)
if /I "!INPUT!"=="!OUTPUT!" set "OUTPUT=!OUTPUT!_converted"

set "FORCE="
if exist "!OUTPUT!" (
  echo.
  echo Output already exists:
  echo !OUTPUT!
  choice /C YN /N /M "Replace it? [Y/N] "
  if errorlevel 2 (
    set "OUTPUT=!OUTPUT!_converted"
    echo Using !OUTPUT! instead.
  ) else (
    set "FORCE=--force"
  )
)

echo.
echo Inspecting source...
if /I "!PYMODE!"=="py" (
  py -3 "%~dp0waw_mpdata_transfer_tool.py" identify "!INPUT!"
) else (
  python "%~dp0waw_mpdata_transfer_tool.py" identify "!INPUT!"
)
if errorlevel 1 (
  echo.
  echo Identification failed. No source file was changed.
  pause
  exit /b 2
)

echo.
echo Converting and authenticating...
if /I "!PYMODE!"=="py" (
  py -3 "%~dp0waw_mpdata_transfer_tool.py" convert "!INPUT!" -o "!OUTPUT!" !FORCE!
) else (
  python "%~dp0waw_mpdata_transfer_tool.py" convert "!INPUT!" -o "!OUTPUT!" !FORCE!
)
set "RESULT=!ERRORLEVEL!"

echo.
if not "!RESULT!"=="0" (
  echo Conversion failed. The source was not changed and no invalid output was accepted.
  echo Encrypted iwm0 files require the original WaW CD key that created the profile.
  echo.
  pause
  exit /b !RESULT!
)

echo Conversion complete:
echo !OUTPUT!
echo.
echo Next, drag that file onto install_unlockstats_mp_drag_and_drop.bat when the
echo intended Plutonium multiplayer profile is active, then run /unlockall once.
echo.
pause
exit /b 0
