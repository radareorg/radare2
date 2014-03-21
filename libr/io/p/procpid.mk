OBJ_PROCPID=io_procpid.o

STATIC_OBJ+=${OBJ_PROCPID}
TARGET_PROCPID=io_procpid.${EXT_SO}
ALL_TARGETS+=${TARGET_PROCPID}

${TARGET_PROCPID}: ${OBJ_PROCPID}
	${CC} $(call libname,io_procpid) \
		${CFLAGS} ${LDFLAGS_LIB} \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -lr_io ${OBJ_PROCPID}
