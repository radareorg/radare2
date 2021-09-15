:: This is a comment
@echo off
:: Preconfigure script for Windows

echo|set /p= === Finding Python...
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
    pip install -UI pip meson ninja
    preconfigure.bat
    exit /b 0
  )
)
echo === Finding Visual Studio...
cl --help > NUL 2> NUL
if %ERRORLEVEL% == 0 (
  echo FOUND
) else (
  if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community" (
    echo "Found community edition"
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
  ) else (
    if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" (
      echo "Found Enterprise edition"
      call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
    ) else (
      if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" (
        echo "Found Professional edition"
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
      ) else (
        if EXIST "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" (
          echo "Found BuildTools"
          call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
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
  git reset --hard 5837915960c2ce862a77c99a374abfb7d18a8534
  popd
)

echo Now you can run 'configure'
cmd
