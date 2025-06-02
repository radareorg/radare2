OBJ_RC6=muta_rc6.o

STATIC_OBJ+=${OBJ_RC6}
TARGET_RC6=muta_rc6.${EXT_SO}

ALL_TARGETS+=${TARGET_RC6}

${TARGET_RC6}: ${OBJ_RC6}
	${CC} $(call libname,muta_rc6) ${LDFLAGS} ${CFLAGS} -o ${TARGET_RC6} ${OBJ_RC6}
