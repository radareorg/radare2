OBJ_MIPS=anal_mips.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_MIPS}
TARGET_MIPS=anal_mips.${EXT_SO}

ALL_TARGETS+=${TARGET_MIPS}

${TARGET_MIPS}: ${OBJ_MIPS}
	${CC} $(call libname,anal_mips) ${CFLAGS} ${CS_CFLAGS} \
		-o anal_mips.${EXT_SO} ${OBJ_MIPS} ${CS_LDFLAGS}
