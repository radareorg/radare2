OBJ_AUTONAME=anal_autoname.o

STATIC_OBJ+=${OBJ_AUTONAME}
TARGET_AUTONAME=anal_autoname.${EXT_SO}

ALL_TARGETS+=${TARGET_AUTONAME}

${TARGET_AUTONAME}: ${OBJ_AUTONAME}
	${CC} $(call libname,anal_autoname) ${LDFLAGS} \
		${CFLAGS} -o anal_autoname.${EXT_SO} ${OBJ_AUTONAME}
