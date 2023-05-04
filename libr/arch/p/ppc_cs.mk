OBJ_PPC_CS=p/ppc_cs/plugin.o
OBJ_PPC_CS+=p/ppc/libvle/vle.o
OBJ_PPC_CS+=p/ppc/libps/libps.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_PPC_CS}
TARGET_PPC_CS=ppc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC_CS}

${TARGET_PPC_CS}: ${OBJ_PPC_CS}
	${CC} ${CFLAGS} $(call libname,ppc_cs) $(CS_CFLAGS) \
		-o ppc_cs.${EXT_SO} ${OBJ_PPC_CS} $(CS_LDFLAGS)
