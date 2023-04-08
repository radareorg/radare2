OBJ_SPARC_GNU=p/sparc/plugin_gnu.o
OBJ_SPARC_GNU+=p/sparc/gnu/sparc-dis.o
OBJ_SPARC_GNU+=p/sparc/gnu/sparc-opc.o

STATIC_OBJ+=${OBJ_SPARC_GNU}
TARGET_SPARC_GNU=arch_sparc_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC_GNU}

${TARGET_SPARC_GNU}: ${OBJ_SPARC_GNU}
	${CC} $(call libname,arch_sparc_gnu) ${CFLAGS} -o arch_sparc_gnu.${EXT_SO} ${OBJ_SPARC_GNU}
