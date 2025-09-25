OBJ_SBPF=anal_sbpf.o

STATIC_OBJ+=${OBJ_SBPF}
TARGET_SBPF=anal_sbpf.${EXT_SO}

ALL_TARGETS+=${TARGET_SBPF}

${TARGET_SBPF}: ${OBJ_SBPF}
	${CC} $(call libname,anal_sbpf) ${LDFLAGS} \
		${CFLAGS} -o anal_sbpf.${EXT_SO} ${OBJ_SBPF}
