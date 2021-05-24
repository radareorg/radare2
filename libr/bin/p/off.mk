OBJ_OFF=bin_off.o

STATIC_OBJ+=${OBJ_OFF}
TARGET_OFF=bin_off.${EXT_SO}

ALL_TARGETS+=${TARGET_OFF}

${TARGET_OFF}: ${OBJ_OFF}
	${CC} $(call libname,bin_off) -shared ${CFLAGS} \
		-o ${TARGET_OFF} ${OBJ_OFF} $(LINK) $(LDFLAGS)
