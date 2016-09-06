OBJ_LANAI=asm_lanai_gnu.o
OBJ_LANAI+=../arch/lanai/gnu/lanai-dis.o
OBJ_LANAI+=../arch/lanai/gnu/lanai-opc.o

STATIC_OBJ+=${OBJ_LANAI}
TARGET_LANAI=asm_lanai_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LANAI}

${TARGET_LANAI}: ${OBJ_LANAI}
	${CC} $(call libname,asm_lanai) ${LDFLAGS} ${CFLAGS} \
		-o asm_lanai_gnu.${EXT_SO} ${OBJ_LANAI}
endif
