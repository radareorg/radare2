OBJ_CIL=p/cil/plugin.o

STATIC_OBJ+=${OBJ_CIL}
TARGET_CIL=arch_cil.${EXT_SO}

ALL_TARGETS+=${TARGET_CIL}

${TARGET_CIL}: ${OBJ_CIL}
	${CC} $(call libname,arch_cil) ${LDFLAGS} ${CFLAGS} -o arch_cil.${EXT_SO} ${OBJ_CIL}