OBJ_PE=./bin_pe.o ./pe/pe.o

STATIC_OBJ+=${OBJ_PE}
TARGET_PE=bin_pe.so

ALL_TARGETS+=${TARGET_PE}

${TARGET_PE}: ${OBJ_PE}
	${CC} ${CFLAGS} -o ${TARGET_PE} ${OBJ_PE}
	@#strip -s ${TARGET_PE}

