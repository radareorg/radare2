OBJ_SH=bp_sh.o

STATIC_OBJ+=${OBJ_SH}
TARGET_SH=bp_sh.${EXT_SO}

ALL_TARGETS+=${TARGET_SH}

${TARGET_SH}: ${OBJ_SH}
	${CC} $(call libname,bp_sh) ${CFLAGS} -o ${TARGET_SH} ${OBJ_SH}
