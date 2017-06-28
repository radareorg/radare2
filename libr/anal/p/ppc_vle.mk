ROOT=../../
OBJ_PPC_VLE=anal_ppc_vle.o
STATIC_OBJ+=${OBJ_PPC_VLE}
OBJ_PPC_VLE+=$(ROOT)/asm/arch/ppc/libvle/vle.o
TARGET_PPC_VLE=anal_ppc_vle.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC_VLE}

${TARGET_PPC_VLE}: ${OBJ_PPC_VLE}
	${CC} $(call libname,anal_ppc_vle) ${CFLAGS} \
		-o anal_ppc_vle.${EXT_SO} ${OBJ_PPC_VLE}
