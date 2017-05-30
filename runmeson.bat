@ECHO OFF
IF EXIST shlr\capstone GOTO START
ECHO [ R2 MESON CLONING CAPSTONE ]
git clone -b next --depth 10 http://github.com/aquynh/capstone.git shlr\capstone
:START
IF "%1"=="-p" GOTO BUILDPROJECT
rem COPY libr\config.mk.meson libr\config.mk
rem COPY libr\config.h.meson libr\config.h
IF EXIST build GOTO BUILD
"c:\Program Files (x86)\python3\python.exe" "c:\Program Files (x86)\python3\scripts\meson.py" --prefix=%CD% build
:BUILD
ECHO [ R2 MESON NINJA BUILD ]
rem copy build\config.h libr\include\config.h
rem copy build\r_version.h libr\include\r_version.h
rem copy build\r_userconf.h libr\include\r_userconf.h
rem copy shlr\spp\config.def.h shlr\spp\config.h
ninja -C build
GOTO EXIT
:BUILDPROJECT
ECHO [ R2 MESON BUILDING VS2015 SLN]
IF EXIST build rd /s /q build
"c:\Program Files (x86)\python3\python.exe" "c:\Program Files (x86)\python3\scripts\meson.py" --prefix=%CD% build --backend=vs2015
:EXIT