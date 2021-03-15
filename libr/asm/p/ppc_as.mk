OBJ_PPC_AS=asm_ppc_as.o

STATIC_OBJ+=${OBJ_PPC_AS}
TARGET_PPC_AS=asm_ppc_as.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PPC_AS}

${TARGET_PPC_AS}: ${OBJ_PPC_AS}
	${CC} $(call libname,asm_ppc_as) ${LDFLAGS} ${CFLAGS} \
		-o ${TARGET_PPC_AS} ${OBJ_PPC_AS}
endif
