:: Build (and eventually install) r2 for windows
@echo off
if "%*" == "clean" (
  wsl rm -rf b vs
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
      copy /y %DESTDIR%\bin\radare2.exe %DESTDIR%\bin\r2.exe
      REM COPY ASAN DLL FROM HERE
      REM "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64"
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
