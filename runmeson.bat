@ECHO OFF
ECHO [ R2 MESON NINJA BUILD ]
IF EXIST shlr\capstone GOTO START
git clone -b next --depth 10 http://github.com/aquynh/capstone.git shlr\capstone
:START
COPY libr\config.mk.meson libr\config.mk
COPY libr\config.h.meson libr\config.h
IF EXIST build GOTO BUILD
meson --prefix=%CD% build
:BUILD
copy build\config.h libr\include\config.h
copy build\r_version.h libr\include\r_version.h
copy build\r_userconf.h libr\include\r_userconf.h
copy shlr\spp\config.def.h shlr\spp\config.h
ninja -C build
