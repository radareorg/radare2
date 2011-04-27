OBJ_DEX=bin_dex.o ../format/dex/dex.o

STATIC_OBJ+=${OBJ_DEX}
TARGET_DEX=bin_dex.${EXT_SO}

ALL_TARGETS+=${TARGET_DEX}

${TARGET_DEX}: ${OBJ_DEX}
	${CC} -shared ${CFLAGS} -o ${TARGET_DEX} ${OBJ_DEX}
	@#strip -s ${TARGET_DEX}
