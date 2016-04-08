OBJ_VSF=bin_vsf.o

STATIC_OBJ+=${OBJ_VSF}
TARGET_VSF=bin_vsf.${EXT_SO}

ALL_TARGETS+=${TARGET_VSF}

${TARGET_VSF}: ${OBJ_VSF}
	${CC} $(call libname,bin_vsf) -shared ${CFLAGS} \
		-o ${TARGET_VSF} ${OBJ_VSF} $(LINK) $(LDFLAGS)
