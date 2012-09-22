OBJ_ARC=asm_arc.o
OBJ_SPARC+=../arch/arc/gnu/arc-dis.o
OBJ_SPARC+=../arch/arc/gnu/arc-opc.o

SHARED2_ARC=$(addprefix ../,${SHARED_ARC})

STATIC_OBJ+=${OBJ_ARC}
SHARED_OBJ+=${SHARED_ARC}
TARGET_ARC=asm_arc.${EXT_SO}

ALL_TARGETS+=${TARGET_ARC}

${TARGET_ARC}: ${OBJ_ARC}
	${CC} $(call libname,asm_arc) ${LDFLAGS} ${CFLAGS} -o ${TARGET_ARC} ${OBJ_ARC} ${SHARED2_ARC}
