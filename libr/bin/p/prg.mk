OBJ_PRG=bin_prg.o

STATIC_OBJ+=${OBJ_PRG}
TARGET_PRG=bin_prg.${EXT_SO}

ALL_TARGETS+=${TARGET_PRG}

${TARGET_PRG}: ${OBJ_PRG}
	${CC} $(call libname,bin_prg) -shared ${CFLAGS} \
		-o ${TARGET_PRG} ${OBJ_PRG} $(LINK) $(LDFLAGS)
