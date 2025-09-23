OBJ_SBPF=anal_sbpf.o

STATIC_OBJ+=${OBJ_SBPF}
TARGET_SBPF=anal_sbpf.${EXT_SO}
ALL_TARGETS+=${TARGET_SBPF}

${TARGET_SBPF}: ${OBJ_SBPF}
	-${CC} $(call libname,anal_sbpf) ${CFLAGS} \
	${OBJ_SBPF} -o ${TARGET_SBPF} ${LINKFLAGS}