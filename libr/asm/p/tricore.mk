OBJ_TRICORE=asm_tricore.o
OBJ_TRICORE+=../arch/tricore/gnu/tricore-dis.o
OBJ_TRICORE+=../arch/tricore/gnu/tricore-opc.o
OBJ_TRICORE+=../arch/tricore/gnu/cpu-tricore.o

STATIC_OBJ+=${OBJ_TRICORE}
TARGET_TRICORE=asm_tricore.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_TRICORE}

${TARGET_TRICORE}: ${OBJ_TRICORE}
	${CC} $(call libname,asm_tricore) ${LDFLAGS} ${CFLAGS} -o asm_tricore.${EXT_SO} ${OBJ_TRICORE}
endif
