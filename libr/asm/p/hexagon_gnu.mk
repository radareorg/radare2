OBJ_HEXAGON_GNU=asm_hexagon_gnu.o
OBJ_HEXAGON_GNU+=../arch/hexagon/gnu/hexagon-dis.o
OBJ_HEXAGON_GNU+=../arch/hexagon/gnu/hexagon-opc.o
OBJ_HEXAGON_GNU+=../arch/hexagon/gnu/safe-ctype.o

STATIC_OBJ+=${OBJ_HEXAGON_GNU}

TARGET_HEXAGON_GNU=asm_hexagon_gnu.${EXT_SO}
ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_HEXAGON_GNU}

${TARGET_HEXAGON_GNU}: ${OBJ_HEXAGON_GNU}
	${CC} $(call libname,asm_hexagon_gnu) ${LDFLAGS} ${CFLAGS} -o ${TARGET_HEXAGON_GNU} ${OBJ_HEXAGON_GNU}
endif
