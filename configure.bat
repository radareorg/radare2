@echo off
REM call preconfigure.bat

echo "Building r2"
meson b -Dsdb_cgen=false --reconfigure
if %ERRORLEVEL% == 0 (
  echo Done
) else (
  echo Try running 'preconfigure'
  exit /b 1
)