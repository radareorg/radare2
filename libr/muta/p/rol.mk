OBJ_ROL=muta_rol.o

STATIC_OBJ+=${OBJ_ROL}
TARGET_ROL=muta_rol.${EXT_SO}

ALL_TARGETS+=${TARGET_ROL}

${TARGET_ROL}: ${OBJ_ROL}
	${CC} $(call libname,muta_rol) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ROL} ${OBJ_ROL}
