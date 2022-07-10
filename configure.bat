@echo off
REM call preconfigure.bat

set MESON_FLAGS=-Dsdb_cgen=false

if "%*" == "asan" (
  set MESON_FLAGS=%MESON_FLAGS% -Dwasan=true
)

if "%*" == "static" (
  set MESON_FLAGS=%MESON_FLAGS% -Dstatic_runtime=true -Dblob=true -Denable_r2r=false -Denable_tests=false
)

if "%*" == "release" (
  set MESON_FLAGS=%MESON_FLAGS% --buildtype=release
)

set PATH=%CD%\prefix\bin;%PATH%
set WORKS=0
if EXIST vs (
  meson vs %MESON_FLAGS% --backend vs --reconfigure && set WORKS=1
) else (
  meson vs %MESON_FLAGS% --backend vs && set WORKS=1
)

if %WORKS% EQU 1 (
  echo Done
) else (
  echo VS failed Try running 'preconfigure'
  exit /b 1
)

set WORKS=0
if EXIST b (
  meson b %MESON_FLAGS% --reconfigure && set WORKS=1
) else (
  meson b %MESON_FLAGS% && set WORKS=1
)

if %WORKS% EQU 1 (
  echo Done
  exit /b 0
) else (
  echo Try running 'preconfigure'
  exit /b 1
)
