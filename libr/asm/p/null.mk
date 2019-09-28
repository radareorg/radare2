OBJ_NULL=asm_null.o

TARGET_NULL=asm_null.${EXT_SO}
STATIC_OBJ+=${OBJ_NULL}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_NULL}
${TARGET_NULL}: ${OBJ_NULL}
	${CC} $(call libname,asm_null) ${LDFLAGS} ${CFLAGS} -o ${TARGET_NULL} ${OBJ_NULL}
endif
