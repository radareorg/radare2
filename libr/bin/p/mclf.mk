OBJ_MCLF=bin_mclf.o

STATIC_OBJ+=${OBJ_MCLF}
TARGET_MCLF=bin_mclf.${EXT_SO}

ALL_TARGETS+=${TARGET_MCLF}

${TARGET_MCLF}: ${OBJ_MCLF}
	${CC} $(call libname,bin_mclf) ${CFLAGS} \
	${OBJ_MCLF} $(LINK) $(LDFLAGS)

