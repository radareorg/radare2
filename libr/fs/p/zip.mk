OBJ_ZIP=fs_zip.o

STATIC_OBJ+=${OBJ_ZIP}
TARGET_ZIP=fs_zip.${EXT_SO}

CFLAGS+=-I$(SPRJ)/zip/lib -I$(SPRJ)/zip
ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

ALL_TARGETS+=${TARGET_ZIP}

${TARGET_ZIP}: ${OBJ_ZIP}
	${CC} $(call libname,fs_zip) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ZIP} ${OBJ_ZIP} ${EXTRA}
