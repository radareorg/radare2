OBJ_V850GNU=asm_v850_gnu.o
OBJ_V850GNU+=../arch/v850/gnu/v850-dis.o
OBJ_V850GNU+=../arch/v850/gnu/v850-opc.o

STATIC_OBJ+=${OBJ_V850GNU}
TARGET_V850GNU=asm_v850_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_V850GNU}

${TARGET_V850GNU}: ${OBJ_V850GNU}
	${CC} $(call libname,asm_v850_gnu) ${LDFLAGS} ${CFLAGS} \
		-o asm_v850_gnu.${EXT_SO} ${OBJ_V850GNU}
endif
