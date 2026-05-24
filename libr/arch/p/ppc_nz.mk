OBJ_PPC_NZ=p/ppc_nz/plugin.o

STATIC_OBJ+=${OBJ_PPC_NZ}
TARGET_PPC_NZ=arch_ppc_nz.${EXT_SO}

ALL_TARGETS+=${TARGET_PPC_NZ}

${TARGET_PPC_NZ}: ${OBJ_PPC_NZ}
	${CC} ${CFLAGS} $(call libname,arch_ppc_nz) $(CS_CFLAGS) \
		-o arch_ppc_nz.${EXT_SO} ${OBJ_PPC_NZ} $(CS_LDFLAGS)
