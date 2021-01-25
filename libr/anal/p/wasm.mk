OBJ_WASM=anal_wasm.o
WASM_ROOT=../asm/arch/wasm
CFLAGS+=-I$(WASM_ROOT)

STATIC_OBJ+=${OBJ_WASM}
TARGET_WASM=anal_wasm.${EXT_SO}
# results in dupped symbol when building statically
#OBJ_WASM+=../../asm/arch/wasm/wasm.o

ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_WASM}
	${CC} $(call libname,anal_wasm) ${LDFLAGS} ${CFLAGS} -o anal_wasm.${EXT_SO} ${OBJ_WASM}
