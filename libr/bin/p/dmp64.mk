OBJ_DMP64=bin_dmp64.o
OBJ_DMP64+=../format/dmp/dmp64.o

STATIC_OBJ+=${OBJ_DMP64}
TARGET_DMP64=bin_dmp64.${EXT_SO}

ALL_TARGETS+=${TARGET_DMP64}

${TARGET_DMP64}: ${OBJ_DMP64}
	-${CC} $(call libname,bin_dmp64) ${CFLAGS} \
	$(OBJ_DMP64) $(LINK) $(LDFLAGS)
