OBJ_HEXAGON=asm_hexagon.o
OBJ_HEXAGON+=../arch/hexagon/hexagon.o
OBJ_HEXAGON+=../arch/hexagon/hexagon_disas.o

CFLAGS +=-I../asm/arch/hexagon

STATIC_OBJ+=${OBJ_HEXAGON}

TARGET_HEXAGON=asm_hexagon.${EXT_SO}
ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_HEXAGON}

${TARGET_HEXAGON}: ${OBJ_HEXAGON}
	${CC} $(call libname,asm_hexagon) ${LDFLAGS} ${CFLAGS} -o ${TARGET_HEXAGON} ${OBJ_HEXAGON}
endif
