WASM_ROOT=$(LIBR)/asm/arch/wasm
OBJ_WASM=asm_wasm.o
OBJ_WASM+=$(WASM_ROOT)/wasm.o
CFLAGS+=-I$(WASM_ROOT)

TARGET_WASM=asm_wasm.${EXT_SO}
STATIC_OBJ+=${OBJ_WASM}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_WASM}
	${CC} $(call libname,asm_wasm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_WASM} ${OBJ_WASM}
endif
