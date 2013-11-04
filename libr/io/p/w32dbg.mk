OBJ_W32DBG=io_w32dbg.o

STATIC_OBJ+=${OBJ_W32DBG}
TARGET_W32DBG=io_w32dbg.${EXT_SO}
ALL_TARGETS+=${TARGET_W32DBG}

${TARGET_W32DBG}: ${OBJ_W32DBG}
	${CC_LIB} $(call libname,io_w32dbg) ${CFLAGS} \
		-L../../util -lr_util \
		-o ${TARGET_W32DBG} ${OBJ_W32DBG}
