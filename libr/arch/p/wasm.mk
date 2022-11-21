OBJ_ARCH_WASM=arch_wasm.o

STATIC_OBJ+=${OBJ_ARCH_WASM}
TARGET_WASM=arch_wasm.${EXT_SO}

ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_ARCH_WASM}
	${CC} $(call libname,arch_wasm) ${LDFLAGS} ${CFLAGS} -o arch_wasm.${EXT_SO} ${OBJ_ARCH_WASM}
