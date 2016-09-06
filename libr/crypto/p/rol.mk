OBJ_ROL=crypto_rol.o

STATIC_OBJ+=${OBJ_ROL}
TARGET_ROL=crypto_rol.${EXT_SO}

ALL_TARGETS+=${TARGET_ROL}

${TARGET_ROL}: ${OBJ_ROL}
	${CC} $(call libname,crypto_rol) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ROL} ${OBJ_ROL}
