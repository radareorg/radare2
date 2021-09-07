@echo off
REM call preconfigure.bat

set PATH=%CD%\prefix\bin;%PATH%
meson vs -Dsdb_cgen=false --backend vs

meson b -Dsdb_cgen=false --reconfigure
if %ERRORLEVEL% == 0 (
  echo Done
  exit /b 0
) else (
  echo Try running 'preconfigure'
  exit /b 1
)