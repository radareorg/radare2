OBJ_HARET=io_haret.o

STATIC_OBJ+=${OBJ_HARET}
TARGET_SHM=io_haret.${EXT_SO}
ALL_TARGETS+=${TARGET_HARET}

${TARGET_HARET}: ${OBJ_HARET}
	${CC} -shared ${CFLAGS} -o ${TARGET_HARET} ${OBJ_HARET} \
		${LDFLAGS_LINKPATH}../../socket -L../../socket -lr_socket \
		${LDFLAGS_LINKPATH}../../lib -L../../lib -lr_lib \
		${LDFLAGS_LINKPATH}.. -L.. -L../../lib -lr_lib -lr_io \
