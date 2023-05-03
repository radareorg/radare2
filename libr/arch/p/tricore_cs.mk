OBJ_TRICORE_CS=p/tricore_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_TRICORE_CS}
TARGET_TRICORE_CS=tricore_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_TRICORE_CS}

${TARGET_TRICORE_CS}: ${OBJ_TRICORE_CS}
	${CC} ${CFLAGS} $(call libname,tricore_cs) $(CS_CFLAGS) \
		-o tricore_cs.${EXT_SO} ${OBJ_TRICORE_CS} $(CS_LDFLAGS)
