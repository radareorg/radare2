OBJ_Z64=bin_z64.o

STATIC_OBJ+=${OBJ_Z64}
TARGET_Z64=bin_z64.${EXT_SO}

ALL_TARGETS+=${TARGET_Z64}

${TARGET_Z64}: ${OBJ_Z64}
	${CC} $(call libname,bin_z64) ${CFLAGS} \
		${OBJ_Z64} \
		$(LINK) $(LDFLAGS)
