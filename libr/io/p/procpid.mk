OBJ_PROCPID=io_procpid.o

STATIC_OBJ+=${OBJ_PROCPID}
TARGET_PROCPID=io_procpid.${EXT_SO}
ALL_TARGETS+=${TARGET_PROCPID}

${TARGET_PROCPID}: ${OBJ_PROCPID}
	${CC} ${CFLAGS} -o ${TARGET_PROCPID} ${LDFLAGS_LIB} \
		$(call libname,io_procpid) \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -L../../lib -lr_lib -lr_io \
		${OBJ_PROCPID}
