SET PATH=C:\MinGW\msys\1.0\bin;C:\Program Files (x86)\Git\bin;%PATH%
echo %PATH%
sh.exe -c "export PATH=/c/mingw/bin:/c/mingw/msys/1.0/bin:/c/Program\ Files\ \(x86\)/Git/bin:${PATH} ; gcc -v"
sh.exe -c "uname | tr 'A-Z' 'a-z'"
sh.exe -c "echo ${CC}"
sh.exe -c "sed -i '/xtensa/d' plugins.def.cfg"
sh.exe -c "export PATH=/c/mingw/bin:/c/mingw/msys/1.0/bin:/c/Program\ Files\ \(x86\)/Git/bin:${PATH} ; ./configure --with-ostype=mingw32 --build=i686-unknown-windows-gnu ; mingw32-make -j1 ; mingw32-make w32dist USE_ZIP=NO"
if "%APPVEYOR%" == "True" (
     appveyor DownloadFile https://raw.githubusercontent.com/radare/radare2-win-installer/master/radare2.iss
     appveyor DownloadFile https://raw.githubusercontent.com/radare/radare2-win-installer/master/radare2.ico
     dir %APPVEYOR_BUILD_FOLDER%\radare2-w32-0.10.0-git
     7z.exe a -tzip %APPVEYOR_BUILD_FOLDER%\radare2-w32-0.10.0.zip %APPVEYOR_BUILD_FOLDER%\radare2-w32-0.10.0
     iscc -DRadare2Location=%APPVEYOR_BUILD_FOLDER%\radare2-w32-0.10.0\* -DLicenseLocation=%APPVEYOR_BUILD_FOLDER%\COPYING.LESSER -DIcoLocation=%APPVEYOR_BUILD_FOLDER%\radare2.ico radare2.iss
)
