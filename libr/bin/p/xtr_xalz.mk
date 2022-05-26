OBJ_XALZ=bin_xtr_xalz.o

STATIC_OBJ+=${OBJ_XALZ}
TARGET_XALZ=bin_xtr_xalz.${EXT_SO}

ifeq (${WITHPIC},1)
ALL_TARGETS+=${TARGET_XALZ}

${TARGET_XALZ}: ${OBJ_XALZ}
	-${CC} $(call libname,bin_xtr_xalz) -shared ${CFLAGS} \
		-o ${TARGET_XALZ} ${OBJ_XALZ} $(LINK) $(LDFLAGS)
endif
