OBJ_PVM=io_pvm.o

STATIC_OBJ+=${OBJ_PVM}
TARGET_PVM=io_pvm.${EXT_SO}
ALL_TARGETS+=${TARGET_PVM}

${TARGET_PVM}: ${OBJ_PVM}
	${CC_LIB} ${CFLAGS} -o ${TARGET_PVM} ${LDFLAGS_LIB} \
		$(call libname,io_pvm) $(LDFLAGS) \
		${LDFLAGS_LINKPATH}../../util -L../../util -lr_util \
		${LDFLAGS_LINKPATH}.. -L.. -lr_io ${OBJ_PVM}
