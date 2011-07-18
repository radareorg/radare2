OBJ_DALVIK=asm_dalvik.o

STATIC_OBJ+=${OBJ_DALVIK}
TARGET_DALVIK=asm_dalvik.${EXT_SO}

ALL_TARGETS+=${TARGET_DALVIK}

${TARGET_DALVIK}: ${OBJ_DALVIK}
	${CC} $(call libname,asm_dalvik) ${LDFLAGS} -I../arch/dalvik ${CFLAGS} -o asm_dalvik.${EXT_SO} ${OBJ_DALVIK}
