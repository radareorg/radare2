OBJ_MACH0=bin_mach0.o ../format/mach0/mach0.o

STATIC_OBJ+=${OBJ_MACH0}
TARGET_MACH0=bin_mach0.${EXT_SO}

ALL_TARGETS+=${TARGET_MACH0}

${TARGET_MACH0}: ${OBJ_MACH0}
	${CC} $(call libname,bin_mach0) ${CFLAGS} -o ${TARGET_MACH0} ${OBJ_MACH0}
