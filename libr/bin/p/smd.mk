OBJ_SMD=bin_smd.o

STATIC_OBJ+=${OBJ_SMD}
TARGET_SMD=bin_smd.${EXT_SO}

ALL_TARGETS+=${TARGET_SMD}

${TARGET_SMD}: ${OBJ_SMD}
	${CC} $(call libname,bin_smd) -shared ${CFLAGS} \
		-o ${TARGET_SMD} ${OBJ_SMD} $(LINK) $(LDFLAGS)
