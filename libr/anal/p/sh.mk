OBJ_SH=anal_sh.o

STATIC_OBJ+=${OBJ_SH}
TARGET_SH=anal_sh.${EXT_SO}

ALL_TARGETS+=${TARGET_SH}

${TARGET_SH}: ${OBJ_SH}
	${CC} $(call libname,anal_sh) ${LDFLAGS} \
		${CFLAGS} -o anal_sh.${EXT_SO} ${OBJ_SH}
