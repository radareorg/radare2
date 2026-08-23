OBJ_HAIKU=io_haiku.o

STATIC_OBJ+=${OBJ_HAIKU}
TARGET_HAIKU=io_haiku.${EXT_SO}
ALL_TARGETS+=${TARGET_HAIKU}

${TARGET_HAIKU}: ${OBJ_HAIKU}
	${CC_LIB} ${CFLAGS} -o ${TARGET_HAIKU} ${LDFLAGS_LIB} \
		$(call libname,io_haiku) $(LDFLAGS) \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -lr_io ${OBJ_HAIKU}
