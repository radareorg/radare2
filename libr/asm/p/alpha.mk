OBJ_ALPHA=asm_alpha.o
OBJ_ALPHA+=../arch/alpha/gnu/alpha-dis.o
OBJ_ALPHA+=../arch/alpha/gnu/alpha-opc.o

STATIC_OBJ+=${OBJ_ALPHA}
TARGET_ALPHA=asm_alpha.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ALPHA}

${TARGET_ALPHA}: ${OBJ_ALPHA}
	${CC} $(call libname,asm_alpha) ${LDFLAGS} \
		-I../arch/alpha ${CFLAGS} -o asm_alpha.${EXT_SO} ${OBJ_ALPHA}
endif
