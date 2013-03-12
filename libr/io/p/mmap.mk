OBJ_MMAP=io_mmap.o

STATIC_OBJ+=${OBJ_MMAP}
TARGET_MMAP=io_mmap.${EXT_SO}
ALL_TARGETS+=${TARGET_MMAP}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif

${TARGET_MMAP}: ${OBJ_MMAP}
	${CC_LIB} $(call libname,io_mmap) ${CFLAGS} -o ${TARGET_MMAP} ${OBJ_MMAP} ${LINKFLAGS}
