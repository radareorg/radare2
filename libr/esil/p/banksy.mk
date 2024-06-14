OBJ_ESIL_BANKSY=esil_banksy.o

STATIC_OBJ+=${OBJ_ESIL_BANKSY}
TARGET_ESIL_BANKSY=esil_banksy.${EXT_SO}

ALL_TARGETS+=${TARGET_ESIL_BANKSY}

${TARGET_ESIL_BANKSY}: ${OBJ_ESIL_BANKSY}
	${CC} -lr_io $(call libname,esil_banksy) ${LDFLAGS} ${CFLAGS} -o esil_banksy.${EXT_SO} ${OBJ_ESIL_BANKSY}
