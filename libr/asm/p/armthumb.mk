OBJ_ARMTHUMB=asm_armthumb.o
OBJ_ARMTHUMB+=../arch/arm/armthumb.o

STATIC_OBJ+=${OBJ_ARMTHUMB}
TARGET_ARMTHUMB=asm_armthumb.${EXT_SO}

ALL_TARGETS+=${TARGET_ARMTHUMB}

${TARGET_ARMTHUMB}: ${OBJ_ARMTHUMB}
	${CC} $(call libname,asm_armthumb) ${LDFLAGS} \
		${CFLAGS} -o asm_armthumb.${EXT_SO} ${OBJ_ARMTHUMB}
