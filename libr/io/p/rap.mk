OBJ_RAP=io_rap.o

STATIC_OBJ+=${OBJ_RAP}
TARGET_RAP=io_rap.${EXT_SO}
ALL_TARGETS+=${TARGET_RAP}

${TARGET_RAP}: ${OBJ_RAP}
	${CC} -shared ${CFLAGS} -o ${TARGET_RAP} ${OBJ_RAP} \
		${LDFLAGS_LINKPATH}../../socket -L../../socket -lr_socket \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}../../cons -L../../cons -lr_cons \
		${LDFLAGS_LINKPATH}.. -L.. -L../../lib -lr_lib -lr_io \
