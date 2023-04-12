OBJ_PPC_CS=anal_ppc_cs.o
OBJ_PPC_CS+=../../arch/p/ppc/libvle/vle.o
OBJ_PPC_CS+=../../arch/p/ppc/libps/libps.o

include $(CURDIR)capstone.mk

STATIC_OBJ+=${OBJ_PPC_CS}
TARGET_PPC_CS=anal_ppc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC_CS}

${TARGET_PPC_CS}: ${OBJ_PPC_CS}
	${CC} ${CFLAGS} $(call libname,anal_ppc_cs) $(CS_CFLAGS) \
		-o anal_ppc_cs.${EXT_SO} ${OBJ_PPC_CS} $(CS_LDFLAGS)
