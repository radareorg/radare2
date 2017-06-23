@ECHO OFF

SET BACKEND=ninja
SET REGEN=
SET RELEASE=
SET BUILDDIR=build

:PARSEARGS
IF NOT "%1"=="" (
	IF "%1"=="-p" (
		SET BACKEND=vs2015
	)
	IF "%1"=="-p2" (
		SET BACKEND=vs2017
	)
	IF "%1"=="-r" (
		SET REGEN=1
	)
	IF "%1"=="--release" (
		SET RELEASE=--buildtype=release
	)
	SHIFT
	GOTO PARSEARGS
)

IF EXIST shlr\capstone GOTO START
ECHO [ R2 MESON CLONING CAPSTONE ]
git clone -b next --depth 10 http://github.com/aquynh/capstone.git shlr\capstone
cd shlr\capstone
rem FOR /r %%p IN (..\capstone-patches\*) DO git apply %%p
git apply ..\capstone-patches\add-mips2.patch
cd ..\..

:START
IF NOT "%RELEASE%"=="" ECHO [ R2 MESON BUILD: RELEASE ]
IF "%REGEN%"=="1" GOTO REBUILD
IF NOT "%BACKEND%"=="ninja" GOTO BUILDPROJECT

IF EXIST %BUILDDIR% GOTO BUILD
python meson.py --prefix=%CD% %BUILDDIR% %RELEASE%

:BUILD
ECHO [ R2 MESON NINJA BUILD ]
copy shlr\spp\config.def.h shlr\spp\config.h
ninja -C %BUILDDIR%
exit /b %errorlevel%

:BUILDPROJECT
ECHO [ R2 MESON BUILDING %BACKEND% SLN]
IF EXIST %BUILDDIR% rd /s /q %BUILDDIR%
python meson.py --prefix=%CD% %BUILDDIR% --backend=%BACKEND% %RELEASE%
GOTO EXIT

:REBUILD
python.exe meson.py --internal regenerate %CD% "%CD%\%BUILDDIR%" --backend %BACKEND% %RELEASE%

:EXIT
