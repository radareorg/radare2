OBJ_BOOTIMG=bin_bootimg.o

STATIC_OBJ+=${OBJ_BOOTIMG}
TARGET_BOOTIMG=bin_bootimg.${EXT_SO}

ALL_TARGETS+=${TARGET_BOOTIMG}

${TARGET_BOOTIMG}: ${OBJ_BOOTIMG}
	${CC} $(call libname,bin_bootimg) -shared ${CFLAGS} \
		-o ${TARGET_BOOTIMG} ${OBJ_BOOTIMG} $(LINK) $(LDFLAGS)
