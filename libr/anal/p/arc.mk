OBJ_ARC=anal_arc.o
OBJ_ARC+=../arch/arc/gnu/arc-dis.o
OBJ_ARC+=../arch/arc/gnu/arc-ext.o
OBJ_ARC+=../arch/arc/gnu/arc-opc.o
OBJ_ARC+=../arch/arc/gnu/arcompact-dis.o

STATIC_OBJ+=${OBJ_ARC}
TARGET_ARC=anal_arc.${EXT_SO}

ALL_TARGETS+=${TARGET_ARC}

${TARGET_ARC}: ${OBJ_ARC}
	${CC} $(call libname,anal_arc) ${LDFLAGS} ${CFLAGS} -o anal_arc.${EXT_SO} ${OBJ_ARC}
