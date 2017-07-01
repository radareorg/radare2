OBJ_HEXAGON=asm_hexagon_gnu.o
OBJ_HEXAGON+=../arch/hexagon/gnu/hexagon-dis.o
OBJ_HEXAGON+=../arch/hexagon/gnu/hexagon-opc.o
OBJ_HEXAGON+=../arch/hexagon/gnu/safe-ctype.o

STATIC_OBJ+=${OBJ_HEXAGON}

TARGET_HEXAGON=asm_hexagon_gnu.${EXT_SO}
ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_HEXAGON}

${TARGET_HEXAGON}: ${OBJ_HEXAGON}
	${CC} $(call libname,asm_hexagon_gnu) ${LDFLAGS} ${CFLAGS} -o ${TARGET_HEXAGON} ${OBJ_HEXAGON}
endif
