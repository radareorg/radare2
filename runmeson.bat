@ECHO OFF
ECHO [ R2 MESON NINJA BUILD ]
COPY libr\config.mk.meson libr\config.mk
COPY libr\config.h.meson libr\config.h
IF EXIST build GOTO BUILD
meson --prefix=C:\Radare2 build
:BUILD
ninja -C build
