@echo off
IF "%R2_VERSION%"=="" (
    SETLOCAL EnableDelayedExpansion
    ECHO %%R2_VERSION%% not set, trying to set automatically
    FOR /F "tokens=* USEBACKQ" %%F IN (`python sys\\version.py`) DO (
        SET VER=%%F
    )
    IF "!VER!"=="" (
        ECHO Failure
        GOTO EXIT
    )
    SET R2_VER=!VER!
) ELSE (
    GOTO CHECK
)
ENDLOCAL & ( SET R2_VERSION=%R2_VER% )

:CHECK
ECHO Using version %R2_VERSION%
IF "%1"=="" ( ECHO Please call this script with the dist folder name. && GOTO EXIT )
SET DIST="%1"

ECHO [ R2 MESON NINJA INSTALL ]
ninja.exe -C build install

ECHO [ R2 SDB GENERATION ]
ECHO TODO


ECHO [ R2 WINDIST FOLDER CREATION ]
MKDIR %DIST%
MOVE bin\*.exe %DIST%\
MOVE lib\*.dll %DIST%\
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
