OBJ_TMS320=anal_tms320.o
OBJ_TMS320+=anal_tms320_c55x_plus.o

STATIC_OBJ+=${OBJ_TMS320}
#OBJ_TMS320+=../../../../../../../../../../../${LTOP}/asm/arch/tms320/tms320_dasm.o
#ROOT=../../../../../../../../../../../../../../../../../../../../../${LTOP}
ROOT=../../
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/tms320_dasm.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/ins.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/c55plus.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/c55plus_decode.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/decode_funcs.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/utils.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/hashtable.o
OBJ_TMS320+=$(ROOT)/asm/arch/tms320/c55x_plus/hashvector.o
TARGET_TMS320=anal_tms320.${EXT_SO}

ALL_TARGETS+=${TARGET_TMS320}

${TARGET_TMS320}: ${OBJ_TMS320} ${SHARED_OBJ}
	${CC} $(call libname,anal_tms320) ${CFLAGS} \
		-I../../include/ -o ${TARGET_TMS320} ${OBJ_TMS320}
