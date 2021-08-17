:: Build (and eventually install) r2 for windows
@echo off
ninja --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  if EXIST b (
  ninja -C b
  echo "Installing r2 in %CD%\prefix"
  set DESTDIR=%CD%\prefix
  ninja -C b install
) else (
  echo Please run configure before make
  exit /b 1
)
) else (
  echo Please run preconfigure
  exit /b 1
)