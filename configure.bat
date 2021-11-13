@echo off
REM call preconfigure.bat

set MESON_FLAGS=-Dsdb_cgen=false

if "%*" == "asan" (
set MESON_FLAGS=%MESON_FLAGS% -Dwasan=true
)

set PATH=%CD%\prefix\bin;%PATH%
if EXIST vs (
meson vs %MESON_FLAGS% --backend vs --reconfigure
) else (
meson vs %MESON_FLAGS% --backend vs
)

if %ERRORLEVEL% == 0 (
  echo Done
) else (
  echo VS failed Try running 'preconfigure'
  exit /b 1
)

if EXIST b (
meson b %MESON_FLAGS% --reconfigure
) else (
meson b %MESON_FLAGS% --buildtype=release
)

if %ERRORLEVEL% == 0 (
  echo Done
  exit /b 0
) else (
  echo Try running 'preconfigure'
  exit /b 1
)