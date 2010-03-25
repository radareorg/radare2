OBJ_PE64=bin_pe64.o ../format/pe/pe64.o

STATIC_OBJ+=${OBJ_PE64}
TARGET_PE64=bin_pe64.${EXT_SO}

ALL_TARGETS+=${TARGET_PE64}

${TARGET_PE64}: ${OBJ_PE64}
	${CC} -shared ${CFLAGS} -o ${TARGET_PE64} ${OBJ_PE64}
	@#strip -s ${TARGET_PE64}
