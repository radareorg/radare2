OBJ_VASM=p/any_vasm/plugin.o

STATIC_OBJ+=${OBJ_VASM}
TARGET_VASM=arch_vasm.${EXT_SO}

ALL_TARGETS+=${TARGET_VASM}

${TARGET_VASM}: ${OBJ_VASM}
	${CC} $(call libname,arch_vasm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_VASM} ${OBJ_VASM}
