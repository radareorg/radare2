OBJ_SPARC=asm_sparc.o
OBJ_SPARC+=../arch/sparc/gnu/sparc-dis.o
OBJ_SPARC+=../arch/sparc/gnu/sparc-opc.o

STATIC_OBJ+=${OBJ_SPARC}

TARGET_SPARC=asm_sparc.so
ALL_TARGETS+=${TARGET_SPARC}

${TARGET_SPARC}: ${OBJ_SPARC}
	${CC} ${CFLAGS} -o ${TARGET_SPARC} ${OBJ_SPARC}
	@#strip -s asm_x86.so

