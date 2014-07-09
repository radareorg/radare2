OBJ_BF=bin_bf.o

STATIC_OBJ+=${OBJ_BF}
TARGET_BF=bin_bf.${EXT_SO}

ALL_TARGETS+=${TARGET_BF}

${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,bin_bf) -shared ${CFLAGS} \
		-o ${TARGET_BF} ${OBJ_BF} $(LINK) $(LDFLAGS)
