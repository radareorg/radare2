OBJ_NINGB=bin_ningb.o

STATIC_OBJ+=${OBJ_NINGB}
TARGET_NINGB=bin_ningb.${EXT_SO}

ALL_TARGETS+=${TARGET_NINGB}

${TARGET_NINGB}: ${OBJ_NINGB}
	${CC} $(call libname,bin_ningb) ${CFLAGS} \
		${OBJ_NINGB} \
		$(LINK) $(LDFLAGS)
