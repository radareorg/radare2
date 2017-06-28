OBJ_PPC_VLE=asm_ppc_vle.o  ../arch/ppc/libvle/vle.o

STATIC_OBJ+=${OBJ_PPC_VLE}
TARGET_SNES=asm_ppc_vle.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_SNES}

${TARGET_SNES}: ${OBJ_PPC_VLE}
	${CC} ${call libname,asm_ppc_vle} ${CFLAGS} -o ${TARGET_SNES} ${OBJ_PPC_VLE}
endif
