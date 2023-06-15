OBJ_MIPS_CS=p/mips/plugin_cs.o
OBJ_MIPS_CS+=p/mips/mipsasm.o

STATIC_OBJ+=$(OBJ_MIPS_CS)
TARGET_MIPS_CS=arch_mips_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS_CS}

${TARGET_MIPS_CS}: ${OBJ_MIPS_CS}
	${CC} ${CFLAGS} $(call libname,arch_mips_cs) $(CS_CFLAGS) \
		-o arch_mips_cs.${EXT_SO} ${OBJ_MIPS_CS} $(CS_LDFLAGS)
