OBJ_PICBASELINE=asm_picbaseline.o

STATIC_OBJ+=${OBJ_PICBASELINE}
TARGET_PICBASELINE=asm_picbaseline.${EXT_SO}

ALL_TARGETS+=${TARGET_PICBASELINE}

${TARGET_PIC18C}: ${OBJ_PICBASELINE}
	${CC} $(call libname,asm_picbaseline) ${LDFLAGS} ${CFLAGS} -o asm_picbaseline.${EXT_SO} ${OBJ_PICBASELINE}
