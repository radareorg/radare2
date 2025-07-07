OBJ_ADD=muta_add.o

STATIC_OBJ+=${OBJ_ADD}
TARGET_ADD=muta_add.${EXT_SO}

ALL_TARGETS+=${TARGET_ADD}

${TARGET_ADD}: ${OBJ_ADD}
	${CC} $(call libname,muta_add) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ADD} ${OBJ_ADD}
