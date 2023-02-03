WASM_ROOT=p/wasm
OBJ_WASM=$(WASM_ROOT)/plugin.o
CFLAGS+=-I$(WASM_ROOT)

STATIC_OBJ+=${OBJ_WASM}
TARGET_WASM=arch_wasm.${EXT_SO}

ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_WASM}
	${CC} ${CFLAGS} $(call libname,arch_wasm) $(CS_CFLAGS) \ -o arch_wasm.${EXT_SO} ${OBJ_WASM} $(CS_LDFLAGS)
