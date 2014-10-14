OBJ_EBC=anal_ebc.o
CFLAGS+=-I../asm/arch/ebc/

STATIC_OBJ+=${OBJ_EBC}
#OBJ_EBC+=../../../../../../../../../../../../../../../../../../../../${LTOP}/asm/arch/ebc/ebc_disas.o
OBJ_EBC+=../../asm/arch/ebc/ebc_disas.o
TARGET_EBC=anal_ebc.${EXT_SO}

ALL_TARGETS+=${TARGET_EBC}

${TARGET_EBC}: ${OBJ_EBC} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_ebc) ${CFLAGS} \
		-o ${TARGET_EBC} ${OBJ_EBC}
