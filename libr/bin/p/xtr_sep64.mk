OBJ_SEP64=bin_xtr_sep64.o

STATIC_OBJ+=${OBJ_SEP64}
TARGET_SEP64=bin_xtr_sep64.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_SEP64}

${TARGET_SEP64}: ${OBJ_SEP64}
	-${CC} $(call libname,bin_xtr_sep64) -shared ${CFLAGS} \
		-o ${TARGET_SEP64} ${OBJ_SEP64} $(LINK) $(LDFLAGS)
endif
