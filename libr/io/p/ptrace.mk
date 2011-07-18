OBJ_PTRACE=io_ptrace.o

STATIC_OBJ+=${OBJ_PTRACE}
TARGET_PTRACE=io_ptrace.${EXT_SO}
ALL_TARGETS+=${TARGET_PTRACE}

${TARGET_PTRACE}: ${OBJ_PTRACE}
	${CC} ${CFLAGS} -o ${TARGET_PTRACE} ${LDFLAGS_LIB} \
		$(call libname,io_ptrace) \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -L../../lib -lr_lib -lr_io \
		${OBJ_PTRACE}
