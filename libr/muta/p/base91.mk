OBJ_B91=muta_base91.o

STATIC_OBJ+=${OBJ_B91}
TARGET_B91=muta_base91.${EXT_SO}

ALL_TARGETS+=${TARGET_B91}

${TARGET_B91}: ${OBJ_B91}
	${CC} $(call libname,muta_base91) ${LDFLAGS} ${CFLAGS} -o ${TARGET_B91} ${OBJ_B91}
