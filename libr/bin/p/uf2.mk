OBJ_UF2=bin_uf2.o

STATIC_OBJ+=${OBJ_UF2}
TARGET_UF2=bin_uf2.${EXT_SO}

ALL_TARGETS+=${TARGET_UF2}

${TARGET_UF2}: ${OBJ_UF2}
	${CC} $(call libname,bin_uf2) -shared ${CFLAGS} \
		-o ${TARGET_UF2} ${OBJ_UF2} $(LINK) $(LDFLAGS)
