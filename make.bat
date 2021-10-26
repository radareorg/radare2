:: Build (and eventually install) r2 for windows
@echo off
ninja --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  if EXIST b (
    ninja -C b
    if %ERRORLEVEL% == 0 (
      echo Installing r2 in %CD%\prefix
      set DESTDIR=%CD%\prefix
      ninja -C b install > NUL
      copy /y %DESTDIR%\bin\radare2.exe %DESTDIR%\bin\r2.exe
      copy /y C:\WINDOWS\System32\vcruntime140.dll %DESTDIR%\bin\vcruntime140.dll
    ) else (
      exit /b 1
    )
  ) else (
    echo Please run configure before make
    exit /b 1
  )
) else (
  echo Please run preconfigure
  exit /b 1
)
