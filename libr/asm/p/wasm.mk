OBJ_WASM=asm_wasm.o

TARGET_WASM=asm_wasm.${EXT_SO}
STATIC_OBJ+=${OBJ_WASM}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_WASM}
${TARGET_WASM}: ${OBJ_WASM}
	${CC} $(call libname,asm_wasm) ${LDFLAGS} ${CFLAGS} -o ${TARGET_WASM} ${OBJ_WASM}
endif
