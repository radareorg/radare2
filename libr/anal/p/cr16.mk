OBJ_CR16=anal_cr16.o
CFLAGS+=-I../asm/arch/cr16/

STATIC_OBJ+=${OBJ_CR16}
#OBJ_CR16+=../../../../../../../../../../../../../../../../../../../../${LTOP}/asm/arch/cr16/cr16_disas.o
OBJ_CR16+=../../asm/arch/cr16/cr16_disas.o
TARGET_CR16=anal_cr16.${EXT_SO}

ALL_TARGETS+=${TARGET_CR16}

${TARGET_CR16}: ${OBJ_CR16} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_cr16) ${CFLAGS} \
		-o ${TARGET_CR16} ${OBJ_CR16}
