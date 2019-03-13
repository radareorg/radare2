OBJ_XTR_PEMIXED=bin_xtr_pemixed.o ../format/pe/pemixed.o

STATIC_OBJ+=${OBJ_XTR_PEMIXED}
TARGET_XTR_PEMIXED=bin_xtr_pemixed.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_XTR_PEMIXED}

${TARGET_XTR_PEMIXED}: ${OBJ_XTR_PEMIXED}
	-${CC} $(call libname,bin_xtr_pemixed) -shared ${CFLAGS} \
		-o ${TARGET_XTR_PEMIXED} ${OBJ_XTR_PEMIXED} $(LINK) $(LDFLAGS)
endif
