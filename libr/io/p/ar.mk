OBJ_AR=io_ar.o ../p/ar/ar.o

STATIC_OBJ+=${OBJ_AR}
TARGET_AR=io_ar.${EXT_SO}
ALL_TARGETS+=${TARGET_AR}

CFLAGS+=-Iar

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_AR}: ${OBJ_AR}
	${CC} $(call libname,io_ar) ${OBJ_AR} ${CFLAGS} \
		${LINKFLAGS} ${LDFLAGS_LIB} $(LDFLAGS)
