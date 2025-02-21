:: This is a comment
@echo off
SETLOCAL EnableDelayedExpansion

:: Preconfigure script for Windows

echo === Finding Python...
python --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo OK
  pip show setuptools > NUL 1> NUL
  if errorlevel 1 (
    echo === Installing setuptools
    python -m pip install -UI pip setuptools
  )
) else (
  echo ERROR
  echo You need to install Python from the windows store or something
  exit /b 1
)

echo === Finding Git...
git --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo OK
) else (
  echo You need to install GIT
  exit /b 1
)
git pull

echo === Testing for meson and ninja...
meson --help > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND
) else (
  echo === Installing pyenv + meson + ninja
  python -m venv venv
  call venv\Scripts\activate.bat
  echo === Testing for meson and ninja...
  meson --help > NUL 2> NUL
  if %ERRORLEVEL% == 0 (
    echo FOUND
  ) else (
    pip install -UI pip ninja
    REM meson==0.59.1 
    pip install git+https://github.com/frida/meson.git@f7f25b19a8d71cebf8e2934733eb041eb6862eee
    preconfigure.bat
    exit /b 0
  )
)

REM vs uses HOST_TARGET syntax, so: x86_amd64 means 32bit compiler for 64bit target
REM: Hosts: x86 amd64 x64
REM: Targets: x86 amd64 x64 arm arm64
REM Detect the host architecture intuitively and easily

IF "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    SET "HOST_ARCH=amd64"
) ELSE IF "%PROCESSOR_ARCHITECTURE%"=="x86" (
    SET "HOST_ARCH=x86"
) ELSE (
    SET "HOST_ARCH=unknown"
)

REM Check if arguments are passed
IF "%~1"=="" (
    echo Your current Host Architecture is !HOST_ARCH!
    ECHO Please select the Target Architecture:
    ECHO 1. x86
    ECHO 2. amd64 [x64]
    ECHO 3. arm
    ECHO 4. arm64
    SET /P "CHOICE=Enter your choice (1-4): "

    REM Set target architecture based on user input
    IF "!CHOICE!"=="1" (
        SET "TARGET_ARCH=x86"
    ) ELSE IF "!CHOICE!"=="2" (
        SET "TARGET_ARCH=amd64"
    ) ELSE IF "!CHOICE!"=="3" (
        SET "TARGET_ARCH=arm"
    ) ELSE IF "!CHOICE!"=="4" (
        SET "TARGET_ARCH=arm64"
    ) ELSE (
        ECHO Invalid choice. Defaulting to amd64.
        SET "TARGET_ARCH=amd64"
    )

    REM Check if target and host are the same and set VSARCH accordingly
    IF "!TARGET_ARCH!"=="!HOST_ARCH!" (
        SET "VSARCH=!HOST_ARCH!"
    ) ELSE (
        SET "VSARCH=!HOST_ARCH!_!TARGET_ARCH!"
    )

) ELSE (
    REM Use provided host_target argument
    SET "VSARCH=%1"
)

ECHO VSARCH is set to: !VSARCH!

echo === Finding Visual Studio...
cl --help > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND
) else if EXIST %VSINSTALLDIR% (
  set "vswherePath=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
  if exist "%vswherePath%" (
      for /f "tokens=*" %%i in ('"%vswherePath%" -property installationName') do (
          echo Visual Studio %%i is installed.
      )
  call %VSINSTALLDIR% + "VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" (
  echo "Found 2022 Enterprise edition"
  call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community" (
  echo "Found 2022 Community edition"
  call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
  echo "Found 2022 BuildTools"
  call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" (
  echo "Found 2019 community edition"
  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
  echo "Found 2019 Enterprise edition"
  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
  echo "Found 2019 Professional edition"
  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
  echo "Found 2019 BuildTools"
  call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
) else (
  echo "Not Found"
  exit /b 1
)

echo Now you can run 'configure'
ENDLOCAL
cmd
