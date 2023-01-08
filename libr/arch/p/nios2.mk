OBJ_NIOS2=p/nios2/plugin.o
OBJ_NIOS2+=p/nios2/nios2-dis.o
OBJ_NIOS2+=p/nios2/nios2-opc.o

STATIC_OBJ+=${OBJ_NIOS2}
TARGET_NIOS2=arch_nios2.${EXT_SO}

ALL_TARGETS+=${TARGET_NIOS2}

${TARGET_NIOS2}: ${OBJ_NIOS2}
	${CC} $(call libname,arch_nios2) ${LDFLAGS} ${CFLAGS} \
		-o arch_nios2.${EXT_SO} ${OBJ_NIOS2}
