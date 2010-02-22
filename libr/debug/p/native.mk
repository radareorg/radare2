OBJ_PTRACE=debug_native.o

STATIC_OBJ+=${OBJ_PTRACE}
TARGET_PTRACE=debug_native.${EXT_SO}

ALL_TARGETS+=${TARGET_PTRACE}

${TARGET_PTRACE}: ${OBJ_PTRACE}
	${CC} ${CFLAGS} -o ${TARGET_PTRACE} \
		${LDFLAGS_LINKPATH}.. -lr_debug \
		${LDFLAGS_LINKPATH}../../lib -lr_lib \
		${LDFLAGS_LINKPATH}../../io -lr_io \
		${LDFLAGS_LINKPATH}../../bp -lr_bp \
		${LDFLAGS_LINKPATH}../../reg -lr_reg \
		${LDFLAGS_LINKPATH}../../util -lr_util \
		${OBJ_PTRACE}
