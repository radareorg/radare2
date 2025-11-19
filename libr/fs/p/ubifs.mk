# radare2: Unsorted Block Images File System - LGPL - Copyright 2025 - MiKi (mikelloc)

OBJ_UBIFS=fs_ubifs.o

# Detect LZO support at build time
HAVE_LZO=$(shell pkg-config --exists lzo2 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_LZO),1)
CFLAGS+=-DHAVE_LZO $(shell pkg-config --cflags lzo2 2>/dev/null)
LDFLAGS+=$(shell pkg-config --libs lzo2 2>/dev/null)
endif

STATIC_OBJ+=${OBJ_UBIFS}
TARGET_UBIFS=fs_ubifs.${EXT_SO}

ALL_TARGETS+=${TARGET_UBIFS}

${TARGET_UBIFS}: ${OBJ_UBIFS}
	${CC} $(call libname,fs_ubifs) ${LDFLAGS} ${CFLAGS} -o ${TARGET_UBIFS} ${OBJ_UBIFS}
