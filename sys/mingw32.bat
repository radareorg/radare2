SET PATH=C:\MinGW\msys\1.0\bin;C:\Program Files (x86)\Git\bin;%PATH%
echo %PATH%
setlocal enabledelayedexpansion
@echo off

rem Read configure.acr and find a version string
for /F "tokens=1,2" %%i in (configure.acr) do (
	set VAR1=%%i
	set VAR2=%%j
	if "!VAR1!" == "VERSION" (
		echo "Read version from configure.acr: !VAR2!"
		set ENV_R2_VER=!VAR2!
		goto :start_build
	)
)

:start_build
sh.exe -c "export PATH=/c/mingw/bin:/c/mingw/msys/1.0/bin:/c/Program\ Files\ \(x86\)/Git/bin:${PATH} ; gcc -v"
sh.exe -c "uname | tr 'A-Z' 'a-z'"
sh.exe -c "echo CC=${CC}"
sh.exe -c "sed -i '/xtensa/d' plugins.def.cfg"
sh.exe -c "export PATH=/c/mingw/bin:/c/mingw/msys/1.0/bin:/c/Program\ Files\ \(x86\)/Git/bin:${PATH} ; ./configure --with-ostype=mingw32 --build=i686-unknown-windows-gnu ; make -j1 CC='gcc -static-libgcc'; make w32dist USE_ZIP=NO"
rem if "%APPVEYOR%" == "True" (
rem     appveyor DownloadFile https://raw.githubusercontent.com/radare/radare2-win-installer/master/radare2.iss
rem     appveyor DownloadFile https://raw.githubusercontent.com/radare/radare2-win-installer/master/radare2.ico
rem     dir %APPVEYOR_BUILD_FOLDER%\radare2-w32-%ENV_R2_VER%
rem     7z.exe a -tzip %APPVEYOR_BUILD_FOLDER%\radare2-w32-%ENV_R2_VER%.zip %APPVEYOR_BUILD_FOLDER%\radare2-w32-%ENV_R2_VER%
rem     iscc -DRadare2Location=%APPVEYOR_BUILD_FOLDER%\radare2-w32-%ENV_R2_VER%\* -DLicenseLocation=%APPVEYOR_BUILD_FOLDER%\COPYING.LESSER -DIcoLocation=%APPVEYOR_BUILD_FOLDER%\radare2.ico radare2.iss
rem )
:end
