OBJ_RC2=muta_rc2.o

STATIC_OBJ+=${OBJ_RC2}
TARGET_RC2=muta_rc2.${EXT_SO}

ALL_TARGETS+=${TARGET_RC2}

${TARGET_RC2}: ${OBJ_RC2}
	${CC} $(call libname,muta_rc2) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RC2} ${OBJ_RC2}
