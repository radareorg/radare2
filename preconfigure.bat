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
  if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Enterprise" (
    echo "Found 2022 Enterprise edition"
    call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
  ) else (
    if EXIST "C:\Program Files\Microsoft Visual Studio\2022\Community" (
      echo "Found 2022 Community edition"
      call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
    ) else (
      if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" (
        echo "Found 2019 community edition"
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
      ) else (
        if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
          echo "Found 2019 Enterprise edition"
          call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
        ) else (
          if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
            echo "Found 2019 Professional edition"
            call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
          ) else (
            if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
              echo "Found 2019 BuildTools"
              call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" %VSARCH%
            ) else (
              echo "Not Found"
              exit /b 1
            )
          )
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
  git checkout radare2-wip
  git reset --hard 9ab2b0bedde459dc86e079718333de4a63bbbacb
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
