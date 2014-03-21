OBJ_MIPS_CS=anal_mips_cs.o
SHARED_MIPS_CS=../../shlr/capstone/libcapstone.a
STATIC_OBJ+=$(OBJ_MIPS_CS)

SHARED_OBJ+=${SHARED_MIPS_CS}
TARGET_MIPS_CS=anal_mips_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS_CS}

${TARGET_MIPS_CS}: ${OBJ_MIPS_CS}
	${CC} ${CFLAGS} $(call libname,anal_mips_cs) \
		-o anal_mips_cs.${EXT_SO} ${OBJ_MIPS_CS}
