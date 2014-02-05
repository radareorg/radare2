OBJ_TMS320=anal_tms320.o
OBJ_TMS320+=anal_tms320_c55plus.o

STATIC_OBJ+=${OBJ_TMS320}
OBJ_TMS320+=../../../../../../../../../../../${LTOP}/asm/arch/tms320/tms320_dasm.o
TARGET_TMS320=anal_tms320.${EXT_SO}

ALL_TARGETS+=${TARGET_TMS320}

${TARGET_TMS320}: ${OBJ_TMS320} ${SHARED_OBJ}
	${CC} $(call libname,anal_tms320) ${CFLAGS} \
		-I../../include/ -o ${TARGET_TMS320} ${OBJ_TMS320}
