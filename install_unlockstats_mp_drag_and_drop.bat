@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Install Plutonium T4 unlockstats_mp
cd /d "%~dp0"

echo.
echo Install Plutonium T4 unlockstats_mp
echo ------------------------------------
echo Target:
echo %%LOCALAPPDATA%%\Plutonium\storage\t4\plutonium\unlockstats_mp
echo.

if "%~1"=="" (
  echo Drag a generated 8192-byte unlockstats_mp file onto this BAT file,
  echo or enter its full path below.
  set /p "INPUT=unlockstats_mp file: "
  set "INPUT=!INPUT:"=!"
) else (
  set "INPUT=%~f1"
)

if not exist "!INPUT!" (
  echo.
  echo ERROR: The input file was not found:
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
  echo Install Python 3 or copy the validated file manually to the target above.
  echo.
  pause
  exit /b 2
)

echo IMPORTANT: Make sure the intended T4 multiplayer profile is active.
choice /C YN /N /M "Validate, back up the current template, and install now? [Y/N] "
if errorlevel 2 exit /b 1

echo.
if /I "!PYMODE!"=="py" (
  py -3 "%~dp0waw_mpdata_transfer_tool.py" install "!INPUT!"
) else (
  python "%~dp0waw_mpdata_transfer_tool.py" install "!INPUT!"
)
set "RESULT=!ERRORLEVEL!"

echo.
if not "!RESULT!"=="0" (
  echo Installation failed. An invalid file was not installed.
  pause
  exit /b !RESULT!
)

echo Installation verified.
echo Return to T4 Multiplayer, run /unlockall once, allow both stats files to
echo finish writing, then exit the game normally.
echo.
pause
exit /b 0
