@echo off
REM call preconfigure.bat

set PATH=%CD%\prefix\bin;%PATH%
if EXIST vs (
meson vs -Dsdb_cgen=false --backend vs --reconfigure
) else (
meson vs -Dsdb_cgen=false --backend vs
)

if EXIST b (
meson b -Dsdb_cgen=false --reconfigure
) else (
meson b -Dsdb_cgen=false --buildtype=release
)

if %ERRORLEVEL% == 0 (
  echo Done
  exit /b 0
) else (
  echo Try running 'preconfigure'
  exit /b 1
)