@echo off
IF "%R2_VERSION%"=="" ( ECHO %%R2_VERSION%% not set. && GOTO EXIT )
IF "%1"=="" ( ECHO Please set dist folder name. && GOTO EXIT )
SET DIST="%1"

ECHO [ R2 MESON NINJA INSTALL ]
ninja.exe -C build install

ECHO [ R2 WINDIST FOLDER CREATION ]
MKDIR %DIST%
MOVE bin\* %DIST%\
MOVE lib\* %DIST%\
XCOPY /S /I shlr\www %DIST%\www
MKDIR %DIST%\share\radare2\%VERSION%\magic
XCOPY /S libr\magic\d\default\* %DIST%\share\radare2\%VERSION%\magic\
MKDIR %DIST%\share\radare2\%VERSION%\syscall
XCOPY /S libr\syscall\d\*.sdb %DIST%\share\radare2\%VERSION%\syscall\
MKDIR %DIST%\share\radare2\%VERSION%\fcnsign
XCOPY /S libr\anal\d\*.sdb %DIST%\share\radare2\%VERSION%\fcnsign
MKDIR %DIST%\share\radare2\%VERSION%\opcodes
XCOPY /S libr\anal\d\*.sdb %DIST%\share\radare2\%VERSION%\opcodes
MKDIR %DIST%\share\doc\radare2
MKDIR %DIST%\include\libr\sdb
MKDIR %DIST%\include\libr\r_util
COPY libr\include\sdb\*.h %DIST%\include\libr\sdb\
COPY libr\include\r_util\*.h %DIST%\include\libr\r_util\
COPY libr\include\*.h %DIST%\include\libr\
COPY doc\fortunes.* %DIST%\share\doc\radare2\
MKDIR %DIST%\share\radare2\%VERSION%\format\dll
COPY libr\bin\d\elf32 %DIST%\share\radare2\%VERSION%\format\
COPY libr\bin\d\elf64 %DIST%\share\radare2\%VERSION%\format\
COPY libr\bin\d\elf_enums %DIST%\share\radare2\%VERSION%\format\
COPY libr\bin\d\pe32 %DIST%\share\radare2\%VERSION%\format\
COPY libr\bin\d\trx %DIST%\share\radare2\%VERSION%\format\
COPY libr\bin\d\dll\*.sdb %DIST%\share\radare2\%VERSION%\format\dll
MKDIR %DIST%\share\radare2\%VERSION%\cons
COPY libr\cons\d\* %DIST%\share\radare2\%VERSION%\cons\
MKDIR %DIST%\share\radare2\%VERSION%\hud
COPY doc\hud %DIST%\share\radare2\%VERSION%\hud\main

:EXIT
