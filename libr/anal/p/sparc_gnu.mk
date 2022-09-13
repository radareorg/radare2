OBJ_SPARC_GNU=anal_sparc_gnu.o
OBJ_SPARC_GNU+=../../asm/arch/sparc/gnu/sparc-dis.o
OBJ_SPARC_GNU+=../../asm/arch/sparc/gnu/sparc-opc.o

STATIC_OBJ+=${OBJ_SPARC_GNU}
TARGET_SPARC=anal_sparc_gnu.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARC}

${TARGET_SPARC}: ${OBJ_SPARC_GNU}
	${CC} $(call libname,anal_sparc_gnu) ${CFLAGS} -o anal_sparc_gnu.${EXT_SO} ${OBJ_SPARC_GNU}
