OBJ_ROT=muta_rot.o

STATIC_OBJ+=${OBJ_ROT}
TARGET_ROT=muta_rot.${EXT_SO}

ALL_TARGETS+=${TARGET_ROT}

${TARGET_ROT}: ${OBJ_ROT}
	${CC} $(call libname,muta_rot) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ROT} ${OBJ_ROT}
