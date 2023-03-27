OBJ_BF=p/bf/plugin.o

STATIC_OBJ+=${OBJ_BF}
TARGET_BF=bf.${EXT_SO}

ALL_TARGETS+=${TARGET_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,bf) ${LDFLAGS} ${CFLAGS} -o bf.${EXT_SO} ${OBJ_BF}
