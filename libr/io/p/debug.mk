OBJ_IODBG=io_debug.o

STATIC_OBJ+=${OBJ_IODBG}
TARGET_IODBG=io_debug.${EXT_SO}

ALL_TARGETS+=${TARGET_IODBG}

${TARGET_IODBG}: ${OBJ_IODBG}
	${CC} ${CFLAGS} -o ${TARGET_IODBG} ${LDFLAGS_LIB} \
		-shared \
		${LDFLAGS_LINKPATH}../../lib -L../../lib -lr_lib \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -lr_io ${OBJ_IODBG}
