OBJ_XTR_FTAB=bin_xtr_ftab.o

STATIC_OBJ+=${OBJ_XTR_FTAB}
TARGET_XTR_FTAB=bin_xtr_ftab.${EXT_SO}

ALL_TARGETS+=${TARGET_XTR_FTAB}

${TARGET_XTR_FTAB}: ${OBJ_XTR_FTAB}
	-${CC} $(call libname,bin_xtr_ftab) -shared ${CFLAGS} \
		-o ${TARGET_XTR_FTAB} ${OBJ_XTR_FTAB} $(LINK) $(LDFLAGS)
