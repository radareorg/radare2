OBJ_ROR=muta_ror.o

STATIC_OBJ+=${OBJ_ROR}
TARGET_ROR=muta_ror.${EXT_SO}

ALL_TARGETS+=${TARGET_ROR}

${TARGET_ROR}: ${OBJ_ROR}
	${CC} $(call libname,muta_ror) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ROR} ${OBJ_ROR}
