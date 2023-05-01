OBJ_SPARC_CS=p/sparc_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=$(OBJ_SPARC_CS)
TARGET_SPARC_CS=sparc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC_CS}

${TARGET_SPARC_CS}: ${OBJ_SPARC_CS}
	${CC} ${CFLAGS} $(call libname,sparc_cs) $(CS_CFLAGS) \
		-o sparc_cs.${EXT_SO} ${OBJ_SPARC_CS} $(CS_LDFLAGS)
