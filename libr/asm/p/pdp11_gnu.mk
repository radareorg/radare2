OBJ_PDP11=asm_pdp11_gnu.o
OBJ_PDP11+=../arch/pdp11/gnu/pdp11-dis.o
OBJ_PDP11+=../arch/pdp11/gnu/pdp11-opc.o

TARGET_PDP11=asm_pdp11_gnu.${EXT_SO}
STATIC_OBJ+=${OBJ_PDP11}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PDP11}
${TARGET_PDP11}: ${OBJ_PDP11}
	${CC} $(call libname,asm_pdp11) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_PDP11} ${OBJ_PDP11}
endif
