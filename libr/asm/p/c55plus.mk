# depends
OBJ_C55PLUS=asm_c55plus.o
OBJ_C55PLUS+=../arch/c55plus/c55plus.o
OBJ_C55PLUS+=../arch/c55plus/decode.o
OBJ_C55PLUS+=../arch/c55plus/decode_funcs.o
OBJ_C55PLUS+=../arch/c55plus/hashtable.o
OBJ_C55PLUS+=../arch/c55plus/hashvector.o
OBJ_C55PLUS+=../arch/c55plus/ins.o
OBJ_C55PLUS+=../arch/c55plus/utils.o

TARGET_C55PLUS=asm_c55plus.${EXT_SO}
ALL_TARGETS+=${TARGET_C55PLUS}
STATIC_OBJ+=${OBJ_C55PLUS}

${TARGET_C55PLUS}: ${OBJ_C55PLUS}
	${CC} $(call libname,asm_c55plus) ${LDFLAGS} ${CFLAGS} ${OBJ_C55PLUS}
