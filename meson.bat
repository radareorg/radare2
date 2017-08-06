@ECHO OFF

SET BACKEND=ninja
SET BUILDDIR=build
SET DEFAULT_LIBRARY=--default-library static
SET RELEASE=
SET BUILD=
SET XP=

rem ######## Meson msvc script ########
rem ## Usage examples:
rem meson.bat -p                         ; Creates vs2015 solution
rem meson.bat -p2                        ; Creates vs2017 solution
rem meson.bat                            ; Compiles the project using ninja build system
rem meson.bat --release                  ; Compiles the project with release flags and ninja build system
rem meson.bat --release --msbuild --xp   ; Compiles the project with msbuild and windows xp support

:PARSEARGS
IF NOT "%1"=="" (
	IF "%1"=="-p" (
		SET BACKEND=vs2015
		SET BUILD=project
	)
	IF "%1"=="-p2" (
		SET BACKEND=vs2017
		SET BUILD=project
	)
	IF "%1"=="-r" (
		SET BUILD=regen
	)
	IF "%1"=="--release" (
		SET RELEASE=--buildtype=release
	)
	IF "%1"=="--msbuild" (
		SET BUILD=msbuild
	)
	IF "%1"=="--xp" (
		rem TODO Not portable check also -p and -p2 options
		SET BACKEND=vs2015
		SET XP=1
	)
	SHIFT
	GOTO PARSEARGS
)

IF EXIST shlr\capstone GOTO START
ECHO [ R2 MESON CLONING CAPSTONE ]
git clone -b next --depth 10 https://github.com/aquynh/capstone.git shlr\capstone
rem Applying capstone patches
rem cd shlr\capstone
rem FOR /r %%p IN (..\capstone-patches\*) DO git apply %%p
rem git apply ..\capstone-patches\add-mips2.patch
rem cd ..\..

:START
IF NOT "%RELEASE%"=="" ECHO [ R2 MESON BUILD: RELEASE ]
IF "%BUILD%"=="regen" GOTO REBUILD
IF "%BUILD%"=="project" GOTO BUILDPROJECT

rem Creating build directory with correct parameters
IF EXIST %BUILDDIR% GOTO BUILD
python meson.py --prefix=%CD% %BUILDDIR% %RELEASE% %DEFAULT_LIBRARY% --backend %BACKEND%

:BUILD
CALL :SDB_BUILD
IF "%BUILD%"=="msbuild" GOTO MSBUILD
ECHO [ R2 MESON NINJA BUILD ]
ninja -C %BUILDDIR%
EXIT /b %errorlevel%

:MSBUILD
ECHO [ R2 MESON MSBUILD ]
IF "%XP%"=="1" (
	python sys\meson_extra.py
)
msbuild %BUILDDIR%\radare2.sln
EXIT /b %errorlevel%

:BUILDPROJECT
ECHO [ R2 MESON BUILDING %BACKEND% SLN]
IF EXIST %BUILDDIR% rd /s /q %BUILDDIR%
python meson.py --prefix=%CD% %BUILDDIR% --backend=%BACKEND% %RELEASE% %DEFAULT_LIBRARY%
IF "%XP%"=="1" (
	python sys\meson_extra.py
)
GOTO EXIT

:REBUILD
python meson.py --internal regenerate %CD% "%CD%\%BUILDDIR%" --backend %BACKEND% %RELEASE% %DEFAULT_LIBRARY%

:EXIT
EXIT /B 0

:SDB_BUILD
ECHO [ SDB BUILD AND GENERATION ]
python sys\meson_sdb.py
EXIT /B 0
