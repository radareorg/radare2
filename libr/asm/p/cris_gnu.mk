OBJ_CRIS=asm_cris_gnu.o
OBJ_CRIS+=../arch/cris/gnu/cris-dis.o
OBJ_CRIS+=../arch/cris/gnu/cris-opc.o

STATIC_OBJ+=${OBJ_CRIS}
TARGET_CRIS=asm_cris_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_CRIS}

${TARGET_CRIS}: ${OBJ_CRIS}
	${CC} $(call libname,asm_cris) ${LDFLAGS} ${CFLAGS} -o asm_cris_gnu.${EXT_SO} ${OBJ_CRIS}
