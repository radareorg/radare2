OBJ_TRICORE=p/tricore/tricore.o
OBJ_TRICORE+=p/tricore/gnu/tricore-dis.o
OBJ_TRICORE+=p/tricore/gnu/tricore-opc.o
OBJ_TRICORE+=p/tricore/gnu/cpu-tricore.o

STATIC_OBJ+=${OBJ_TRICORE}
TARGET_TRICORE=tricore.${EXT_SO}

ALL_TARGETS+=${TARGET_TRICORE}

${TARGET_TRICORE}: ${OBJ_TRICORE}
	${CC} $(call libname,tricore) ${LDFLAGS} ${CFLAGS} \
		-o $(TARGET_TRICORE) $(OBJ_TRICORE)
