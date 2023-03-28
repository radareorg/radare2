OBJ_ARC=p/arc/plugin.o
OBJ_ARC+=p/arc/gnu/arc-dis.o
OBJ_ARC+=p/arc/gnu/arc-ext.o
OBJ_ARC+=p/arc/gnu/arc-opc.o
OBJ_ARC+=p/arc/gnu/arcompact-dis.o

STATIC_OBJ+=${OBJ_ARC}
TARGET_ARC=arc.${EXT_SO}

ALL_TARGETS+=${TARGET_ARC}

${TARGET_ARC}: ${OBJ_ARC}
	${CC} $(call libname,arc) ${LDFLAGS} ${CFLAGS} -o arc.${EXT_SO} ${OBJ_ARC}
