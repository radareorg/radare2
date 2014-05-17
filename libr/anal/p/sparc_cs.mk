OBJ_SPARC_CS=anal_sparc_cs.o
CFLAGS+=-I../../shlr/capstone/include
STATIC_OBJ+=${OBJ_SPARC_CS}
SHARED_SPARC_CS=../../shlr/capstone/libcapstone.a

SHARED_OBJ+=${SHARED_SPARC_CS}
TARGET_SPARC_CS=anal_sparc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC_CS}

${TARGET_SPARC_CS}: ${OBJ_SPARC_CS}
	${CC} ${CFLAGS} $(call libname,anal_sparc_cs) \
		-o anal_sparc_cs.${EXT_SO} ${OBJ_SPARC_CS}
