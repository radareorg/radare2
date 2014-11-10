OBJ_SPARC=anal_sparc.o

STATIC_OBJ+=${OBJ_SPARC}
TARGET_SPARC=anal_sparc.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC}

${TARGET_SPARC}: ${OBJ_SPARC}
	${CC} $(call libname,anal_sparc) ${CFLAGS} -o anal_sparc.${EXT_SO} ${OBJ_SPARC}
