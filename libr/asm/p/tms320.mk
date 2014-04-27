OBJ_TMS320=asm_tms320.o
OBJ_TMS320+=../arch/tms320/tms320_dasm.o

# looks ugly as radare2 build system is terrible

OBJ_TMS320+=../arch/tms320/c55x_plus/c55plus.o \
	    ../arch/tms320/c55x_plus/c55plus_decode.o \
	    ../arch/tms320/c55x_plus/decode_funcs.o \
	    ../arch/tms320/c55x_plus/hashtable.o \
	    ../arch/tms320/c55x_plus/hashvector.o \
	    ../arch/tms320/c55x_plus/ins.o \
	    ../arch/tms320/c55x_plus/utils.o

STATIC_OBJ+=${OBJ_TMS320}
TARGET_TMS320=asm_tms320.${EXT_SO}

ALL_TARGETS+=${TARGET_TMS320}

${TARGET_TMS320}: ${OBJ_TMS320}
	${CC} $(call libname,asm_tms320) ${LDFLAGS} ${CFLAGS} ${OBJ_TMS320}
