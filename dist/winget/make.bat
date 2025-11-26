@echo off
REM Build radare2 for Windows and create zip package for winget
if "%*" == "clean" (
  rmdir /s /q b 2> NUL
  rmdir /s /q prefix 2> NUL
  del radare2-6.0.7-w64.zip 2> NUL
  exit /b 0
)

call ninja.exe --version > NUL 2> NUL && (
  if EXIST b (
    call ninja.exe -C b -j 2 && (
      echo Installing r2 in %CD%\prefix
      set DESTDIR=%CD%\prefix
      rmdir /q /s prefix 2> NUL
      call ninja -C b install > NUL
      copy /y C:\WINDOWS\System32\vcruntime140.dll %DESTDIR%\bin\vcruntime140.dll
      REM Create zip package
      if EXIST radare2-6.0.7-w64.zip del radare2-6.0.7-w64.zip
      powershell "Compress-Archive -Path prefix\* -DestinationPath radare2-6.0.7-w64.zip"
      echo Zip package created: radare2-6.0.7-w64.zip
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