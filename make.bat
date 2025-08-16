:: Build (and eventually install) r2 for windows
@echo off
if "%*" == "clean" (
  REM wsl rm -rf b vs
  rmdir /s /q b 2> NUL
  rmdir /s /q vs 2> NUL
  exit /b 0
)

call ninja.exe --version > NUL 2> NUL && (
  if EXIST b (
    REM meson compile -C b
    call ninja.exe -C b -j 2 && (
      echo Installing r2 in %CD%\prefix
      set DESTDIR=%CD%\prefix
      rmdir /q /s prefix 2> NUL
      REM meson install -C b
      call ninja -C b install > NUL
      copy /y C:\WINDOWS\System32\vcruntime140.dll %DESTDIR%\bin\vcruntime140.dll
      exit /b 0
    ) || (
      echo Ninja compilation has failed
      exit /b 1
    )
  ) else (
    echo Please run configure before make
    exit /b 1
  )
) || (
  echo Cannot find the ninja. Please run preconfigure
  exit /b 1
)
