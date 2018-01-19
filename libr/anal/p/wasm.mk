WASM_ROOT=$(LIBR)/asm/arch/wasm
OBJ_WASM=anal_wasm.o
CFLAGS+=-I$(WASM_ROOT)

STATIC_OBJ+=${OBJ_WASM}
TARGET_WASM=anal_wasm.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_WASM+=$(WASM_ROOT)/wasm.o
endif

ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_WASM}
	${CC} $(call libname,anal_wasm) ${LDFLAGS} ${CFLAGS} -o anal_wasm.${EXT_SO} ${OBJ_WASM}
