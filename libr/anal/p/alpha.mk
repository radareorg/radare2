OBJ_ALPHA=anal_alpha.o
OBJ_ALPHA+=../../asm/arch/alpha/gnu/alpha-dis.o
OBJ_ALPHA+=../../asm/arch/alpha/gnu/alpha-opc.o

STATIC_OBJ+=${OBJ_ALPHA}
TARGET_ALPHA=anal_alpha.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_ALPHA}

${TARGET_ALPHA}: ${OBJ_ALPHA}
	${CC} $(call libname,anal_alpha) ${LDFLAGS} \
		-I../../asm/arch/alpha ${CFLAGS} -o anal_alpha.${EXT_SO} ${OBJ_ALPHA}
endif
