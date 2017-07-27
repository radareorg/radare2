@echo off

SET BUILDER=ninja
SET DIST=

:PARSEARGS
IF NOT "%1"=="" (
	IF "%1"=="--msbuild" (
		SET BUILDER=msbuild
	) ELSE (
        SET DIST=%1
    )
	SHIFT
	GOTO PARSEARGS
)

:START
IF "%DIST%"=="" ( ECHO Please call this script with the dist folder name. && GOTO EXIT )
IF "%R2_VERSION%"=="" (
    SETLOCAL EnableDelayedExpansion
    ECHO %%R2_VERSION%% not set, trying to set automatically...
    FOR /F "tokens=* USEBACKQ" %%F IN (`python sys\\version.py`) DO (
        SET VER=%%F
    )
    IF "!VER!"=="" (
        ECHO Failed.
        GOTO EXIT
    )
    SET R2_VER=!VER!
) ELSE (
    GOTO CHECK
)
ENDLOCAL & ( SET "R2_VERSION=%R2_VER%" )

:CHECK
ECHO Using version %R2_VERSION%

IF "%BUILDER%"=="ninja" (
    ECHO [ R2 MESON NINJA INSTALL ]
    ninja.exe -C build install
)
IF "%BUILDER%"=="msbuild" (
    ECHO [ R2 MSBUILD INSTALL ]

    IF EXIST bin ( RD /s /q bin )
    MKDIR bin
    FOR /F "tokens=*" %%F IN (' dir /s /b build\binr\*.exe ') DO COPY %%F bin\

    IF EXIST lib ( RD /s /q lib )
    MKDIR lib
    FOR /F "tokens=*" %%F IN (' dir /s /b build\libr\*.dll ') DO COPY %%F lib\
)

ECHO [ R2 SDB GENERATION ]
ECHO TODO

ECHO [ R2 WINDIST FOLDER CREATION ]
MKDIR %DIST%
MOVE bin\*.exe %DIST%\
MOVE lib\*.dll %DIST%\
XCOPY /S /I shlr\www %DIST%\www
MKDIR %DIST%\share\radare2\%R2_VERSION%\magic
XCOPY /S libr\magic\d\default\* %DIST%\share\radare2\%R2_VERSION%\magic\
MKDIR %DIST%\share\radare2\%R2_VERSION%\syscall
XCOPY /S libr\syscall\d\*.sdb %DIST%\share\radare2\%R2_VERSION%\syscall\
MKDIR %DIST%\share\radare2\%R2_VERSION%\fcnsign
XCOPY /S libr\anal\d\*.sdb %DIST%\share\radare2\%R2_VERSION%\fcnsign\
MKDIR %DIST%\share\radare2\%R2_VERSION%\opcodes
XCOPY /S libr\anal\d\*.sdb %DIST%\share\radare2\%R2_VERSION%\opcodes\
MKDIR %DIST%\share\doc\radare2
MKDIR %DIST%\include\libr\sdb
MKDIR %DIST%\include\libr\r_util
COPY libr\include\sdb\*.h %DIST%\include\libr\sdb\
COPY libr\include\r_util\*.h %DIST%\include\libr\r_util\
COPY libr\include\*.h %DIST%\include\libr\
COPY doc\fortunes.* %DIST%\share\doc\radare2\
MKDIR %DIST%\share\radare2\%R2_VERSION%\format\dll
COPY libr\bin\d\elf32 %DIST%\share\radare2\%R2_VERSION%\format\
COPY libr\bin\d\elf64 %DIST%\share\radare2\%R2_VERSION%\format\
COPY libr\bin\d\elf_enums %DIST%\share\radare2\%R2_VERSION%\format\
COPY libr\bin\d\pe32 %DIST%\share\radare2\%R2_VERSION%\format\
COPY libr\bin\d\trx %DIST%\share\radare2\%R2_VERSION%\format\
COPY libr\bin\d\dll\*.sdb %DIST%\share\radare2\%R2_VERSION%\format\dll\
MKDIR %DIST%\share\radare2\%R2_VERSION%\cons
COPY libr\cons\d\* %DIST%\share\radare2\%R2_VERSION%\cons\
MKDIR %DIST%\share\radare2\%R2_VERSION%\hud
COPY doc\hud %DIST%\share\radare2\%R2_VERSION%\hud\main

:EXIT
