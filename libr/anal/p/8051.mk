OBJ_8051=anal_8051.o

STATIC_OBJ+=${OBJ_8051}
#OBJ_8051+=../../../../../../../../../../../../../../../../../../../../${LTOP}/asm/arch/8051/8051.o
#OBJ_8051+=${LTOP}/asm/arch/8051/8051.o
#OBJ_8051+=../../asm/arch/8051/8051.o
TARGET_8051=anal_8051.${EXT_SO}

ALL_TARGETS+=${TARGET_8051}

${TARGET_8051}: ${OBJ_8051}
	${CC} $(call libname,anal_z80) ${LDFLAGS} ${CFLAGS} -o anal_8051.${EXT_SO} ${OBJ_8051}
