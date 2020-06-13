OBJ_BA2=anal_ba2.o
CFLAGS+=-I../asm/arch/ba2

STATIC_OBJ+=${OBJ_BA2}
#OBJ_BA2+=../../../../../../../../../../../../../../../../../../../../${LTOP}/asm/arch/ba2/ba2.o
#OBJ_BA2+=${LTOP}/asm/arch/8051/8051.o
#OBJ_BA2+=../../asm/arch/8051/8051.o
TARGET_BA2=anal_ba2.${EXT_SO}

ALL_TARGETS+=${TARGET_BA2}

${TARGET_BA2}: ${OBJ_BA2}
	${CC} $(call libname,anal_ba2) ${LDFLAGS} ${CFLAGS} -o anal_ba2.${EXT_SO} ${OBJ_BA2}
