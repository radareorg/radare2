OBJ_FS=bin_fs.o

STATIC_OBJ+=${OBJ_FS}
TARGET_FS=bin_fs.${EXT_SO}

ALL_TARGETS+=${TARGET_FS}

${TARGET_FS}: ${OBJ_FS}
	${CC} $(call libname,bin_fs) -shared ${CFLAGS} \
		-o ${TARGET_FS} ${OBJ_FS} $(LINK) $(LDFLAGS)
