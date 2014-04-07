OBJ_EDB=io_edb.o

STATIC_OBJ+=${OBJ_EDB}
TARGET_EDB=io_edb.${EXT_SO}
ALL_TARGETS+=${TARGET_EDB}

${TARGET_EDB}: ${OBJ_EDB}
	${CC} ${CFLAGS} -o ${TARGET_EDB} ${OBJ_EDB} \
		$(call libname,io_edb) \
		${LDFLAGS_LINKPATH}../../socket -L../../socket -lr_socket \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}../../cons -L../../cons -lr_cons \
		${LDFLAGS_LINKPATH}.. -L.. -lr_io
