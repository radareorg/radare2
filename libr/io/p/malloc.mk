OBJ_MALLOC=io_malloc.o

STATIC_OBJ+=${OBJ_MALLOC}
TARGET_MALLOC=io_malloc.${EXT_SO}
ALL_TARGETS+=${TARGET_MALLOC}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif

${TARGET_MALLOC}: ${OBJ_MALLOC}
	${CC_LIB} $(call libname,io_malloc) ${CFLAGS} -o ${TARGET_MALLOC} ${OBJ_MALLOC} ${LINKFLAGS}
