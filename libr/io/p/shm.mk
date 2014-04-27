OBJ_SHM=io_shm.o

STATIC_OBJ+=${OBJ_SHM}
TARGET_SHM=io_shm.${EXT_SO}
ALL_TARGETS+=${TARGET_SHM}

ifeq (${WITHPIC},0)
LINKFLAGS+=../../util/libr_util.a
LINKFLAGS+=../../io/libr_io.a
else
LINKFLAGS+=-L../../util -lr_util
LINKFLAGS+=-L.. -lr_io
endif

${TARGET_SHM}: ${OBJ_SHM}
	${CC_LIB} $(call libname,io_shm) ${CFLAGS} -o ${TARGET_SHM} ${OBJ_SHM} ${LINKFLAGS}
