OBJ_DES=muta_des.o

STATIC_OBJ+=${OBJ_DES}
TARGET_DES=muta_des.${EXT_SO}

ALL_TARGETS+=${TARGET_DES}

${TARGET_DES}: ${OBJ_DES}
	${CC} $(call libname,muta_des) ${LDFLAGS} ${CFLAGS} -o ${TARGET_DES} ${OBJ_DES}
