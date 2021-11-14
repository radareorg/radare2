:: Build (and eventually install) r2 for windows
@echo off
if "%*" == "clean" (
	wsl rm -rf b vs
	exit /b 0
)
ninja --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  if EXIST b (
    REM meson compile -C b
    ninja -C b
    if %ERRORLEVEL% == 0 (
      echo Installing r2 in %CD%\prefix
      set DESTDIR=%CD%\prefix
      rmdir /s prefix
      REM meson install -C b
      ninja -C b install > NUL
      copy /y %DESTDIR%\bin\radare2.exe %DESTDIR%\bin\r2.exe
      REM COPY ASAN DLL FROM HERE
      REM "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64"
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
