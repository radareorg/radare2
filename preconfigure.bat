:: This is a comment
@echo off
:: Preconfigure script for Windows

echo === Finding Python...
python --version > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo OK
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
    pip install -UI pip meson==0.59.1 ninja==1.9.0
    preconfigure.bat
    exit /b 0
  )
)

REM vs uses HOST_TARGET syntax, so: x86_amd64 means 32bit compiler for 64bit target
REM: Hosts: x86 amd64 x64
REM: Targets: x86 amd64 x64 arm arm64
if "%*" == "x86" (
  set VSARCH=x86
) ELSE (
  set VSARCH=x86_amd64
)

echo === Finding Visual Studio...
cl --help > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND
) else (
  if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" (
    echo "Found community edition"
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else (
    if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
      echo "Found Enterprise edition"
      call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
    ) else (
      if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        echo "Found Professional edition"
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
      ) else (
        if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
          echo "Found BuildTools"
          call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
        ) else (
          echo "Not Found"
          exit /b 1
        )
      )
    )
  )
)

if EXIST "libr\asm\arch\arm\v35arm64\arch-arm64" (
  echo "v35arm64 ok"
) else (
  pushd "libr\asm\arch\arm\v35arm64"
  git clone https://github.com/radareorg/vector35-arch-arm64 arch-arm64
  cd arch-arm64
  git checkout radare2
  git reset --hard 3c5eaba46dab72ecb7d5f5b865a13fdeee95b464
  popd
)

if EXIST "libr\asm\arch\arm\v35arm64\arch-armv7" (
  echo "v35armv7 ok"
) else (
  pushd "libr\asm\arch\arm\v35arm64"
  git clone https://github.com/radareorg/vector35-arch-armv7 arch-armv7
  cd arch-armv7
  git checkout radare2
  git reset --hard dde39f69ffea19fc37e681874b12cb4707bc4f30
  popd
)

echo Now you can run 'configure'
cmd
