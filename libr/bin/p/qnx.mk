OBJ_QNX+=bin_qnx.o 


STATIC_OBJ+=${OBJ_QNX}
TARGET_QNX=bin_qnx.${EXT_SO}

ALL_TARGETS+=${TARGET_QNX}

${TARGET_QNX}: ${OBJ_QNX}
	${CC} $(call libname,bin_qnx) -shared ${CFLAGS} \
		-o ${TARGET_QNX} $(LINK) $(LDFLAGS)