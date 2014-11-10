OBJ_SPARC=asm_sparc_gnu.o
OBJ_SPARC+=../arch/sparc/gnu/sparc-dis.o
OBJ_SPARC+=../arch/sparc/gnu/sparc-opc.o

STATIC_OBJ+=${OBJ_SPARC}

TARGET_SPARC=asm_sparc_gnu.${EXT_SO}
ALL_TARGETS+=${TARGET_SPARC}

${TARGET_SPARC}: ${OBJ_SPARC}
	${CC} $(call libname,asm_sparc_gnu) ${LDFLAGS} ${CFLAGS} -o ${TARGET_SPARC} ${OBJ_SPARC}
