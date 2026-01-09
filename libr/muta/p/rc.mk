OBJ_RC=muta_rc.o

STATIC_OBJ+=${OBJ_RC}
TARGET_RC=muta_rc.${EXT_SO}

ALL_TARGETS+=${TARGET_RC}

${TARGET_RC}: ${OBJ_RC}
	${CC} $(call libname,muta_rc) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RC} ${OBJ_RC}