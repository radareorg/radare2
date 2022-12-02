OBJ_X86NZ=p/x86_nz/plugin.o

STATIC_OBJ+=${OBJ_X86NZ}
TARGET_X86NZ=arch_x86_nz.${EXT_SO}

ALL_TARGETS+=${TARGET_X86NZ}

${TARGET_X86NZ}: ${OBJ_X86NZ}
	${CC} ${CFLAGS} $(call libname,arch_x86_nz) $(CS_CFLAGS) \
		-o arch_x86_nz.${EXT_SO} ${OBJ_X86NZ} $(CS_LDFLAGS)
