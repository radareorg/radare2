OBJ_LANAI=anal_lanai_gnu.o
OBJ_LANAI+=../../asm/arch/lanai/gnu/lanai-dis.o
OBJ_LANAI+=../../asm/arch/lanai/gnu/lanai-opc.o

STATIC_OBJ+=${OBJ_LANAI}
TARGET_LANAI=anal_lanai_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_LANAI}

${TARGET_LANAI}: ${OBJ_LANAI}
	${CC} $(call libname,anal_lanai) ${LDFLAGS} ${CFLAGS} \
		-o anal_lanai_gnu.${EXT_SO} ${OBJ_LANAI}
endif
