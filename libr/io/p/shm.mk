OBJ_SHM=io_shm.o

STATIC_OBJ+=${OBJ_SHM}
TARGET_SHM=io_shm.${EXT_SO}
ALL_TARGETS+=${TARGET_SHM}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../lib/libr_lib.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../lib -lr_lib
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -L../../lib -lr_lib -lr_io 
endif

${TARGET_SHM}: ${OBJ_SHM}
	${CC_LIB} $(call libname,io_shm) ${CFLAGS} -o ${TARGET_SHM} ${OBJ_SHM} ${LINKFLAGS}
