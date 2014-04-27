OBJ_PPC_CS=anal_ppc_cs.o
CFLAGS+=-I../../shlr/capstone/include
SHARED_PPC_CS=../../shlr/capstone/libcapstone.a
STATIC_OBJ+=${OBJ_PPC_CS}

SHARED_OBJ+=${SHARED_PPC_CS}
TARGET_PPC_CS=anal_ppc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC_CS}

${TARGET_PPC_CS}: ${OBJ_PPC_CS}
	${CC} ${CFLAGS} $(call libname,anal_ppc_cs) \
		-o anal_ppc_cs.${EXT_SO} ${OBJ_PPC_CS}
