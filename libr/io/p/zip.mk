OBJ_ZIP=io_zip.o

STATIC_OBJ+=${OBJ_ZIP}
TARGET_ZIP=io_zip.${EXT_SO}
ALL_TARGETS+=${TARGET_ZIP}

# XXX must use shlr/zip/deps.mk
CFLAGS+=-I../../subprojects/otezip/src/include/otezip

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

# Link against system libzip when USE_LIB_ZIP=1, otherwise otezip
ifeq ($(USE_LIB_ZIP),1)
LINKFLAGS+=$(LIBZIP)
else
LINKFLAGS+=../../../subprojects/otezip/libotezip.a
endif

${TARGET_ZIP}: ${OBJ_ZIP}
	${CC_LIB} $(call libname,io_zip) ${CFLAGS} -o ${TARGET_ZIP} ${OBJS} ${LINKFLAGS}
