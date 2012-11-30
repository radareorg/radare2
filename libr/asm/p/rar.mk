OBJ_RAR=asm_rar.o
# XXX

STATIC_OBJ+=${OBJ_RAR}
TARGET_RAR=asm_rar.${EXT_SO}

ALL_TARGETS+=${TARGET_RAR}

${TARGET_RAR}: ${OBJ_RAR}
	${CC} $(call libname,asm_rar) ${LDFLAGS} ${CFLAGS} -o asm_rar.${EXT_SO} ${OBJ_RAR}
