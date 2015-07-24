OBJ_V810=anal_v810.o

STATIC_OBJ+=${OBJ_V810}
OBJ_V810+=../../asm/arch/v810/v810_disas.o
TARGET_V810=anal_v810.${EXT_SO}

CFLAGS+=-I../asm/arch/v810/

ALL_TARGETS+=${TARGET_V810}

${TARGET_V810}: ${OBJ_V810} ${SHARED_OBJ}
	$(call pwd)
	${CC} $(call libname,anal_v810) ${CFLAGS} \
		-I../../asm/arch/v810/ -o ${TARGET_V810} ${OBJ_V810}
