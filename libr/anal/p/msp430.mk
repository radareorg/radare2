OBJ_msp430=anal_msp430.o
CFLAGS+=-I../asm/arch/msp430/

STATIC_OBJ+=${OBJ_msp430}
OBJ_msp430+=../../asm/arch/msp430/msp430_disas.o
TARGET_msp430=anal_msp430.${EXT_SO}

ALL_TARGETS+=${TARGET_msp430}

${TARGET_msp430}: ${OBJ_msp430} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_msp430) ${CFLAGS} \
		-o ${TARGET_msp430} ${OBJ_msp430}
