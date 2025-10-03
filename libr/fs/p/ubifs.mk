# radare2: Unsorted Block Images File System - LGPL - Copyright 2025 - MiKi (mikelloc)

OBJ_UBIFS=fs_ubifs.o

STATIC_OBJ+=${OBJ_UBIFS}
TARGET_UBIFS=fs_ubifs.${EXT_SO}

ALL_TARGETS+=${TARGET_UBIFS}

${TARGET_UBIFS}: ${OBJ_UBIFS}
	${CC} $(call libname,fs_ubifs) ${LDFLAGS} ${CFLAGS} -o ${TARGET_UBIFS} ${OBJ_UBIFS}
