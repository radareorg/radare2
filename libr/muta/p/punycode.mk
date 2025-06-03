OBJ_PUNY=muta_punycode.o

STATIC_OBJ+=${OBJ_PUNY}
TARGET_PUNY=muta_punycode.${EXT_SO}

ALL_TARGETS+=${TARGET_PUNY}

${TARGET_PUNY}: ${OBJ_PUNY}
	${CC} $(call libname,muta_punycode) ${LDFLAGS} ${CFLAGS} -o ${TARGET_PUNY} ${OBJ_PUNY}
