WASM_ROOT=../../asm/arch/wasm
OBJ_WASM=anal_wasm.o
OBJ_WASM+=$(WASM_ROOT)/wasm.o
CFLAGS+=-I$(WASM_ROOT)

STATIC_OBJ+=${OBJ_WASM}
TARGET_WASM=anal_wasm.${EXT_SO}

ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_WASM}
	${CC} $(call libname,anal_wasm) ${LDFLAGS} ${CFLAGS} -o anal_wasm.${EXT_SO} ${OBJ_WASM}
