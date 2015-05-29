OBJ_ZIMG=bin_zimg.o ../format/zimg/zimg.o

STATIC_OBJ+=${OBJ_ZIMG}
TARGET_ZIMG=bin_zimg.${EXT_SO}

ALL_TARGETS+=${TARGET_ZIMG}

${TARGET_ZIMG}: ${OBJ_ZIMG}
	${CC} $(call libname,bin_zimg) -shared ${CFLAGS} \
		-o ${TARGET_ZIMG} ${OBJ_ZIMG} $(LINK) $(LDFLAGS)
