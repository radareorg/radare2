OBJ_MBN=bin_mbn.o

STATIC_OBJ+=${OBJ_MBN}
TARGET_MBN=bin_mbn.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_MBN}

${TARGET_MBN}: ${OBJ_MBN}
	-${CC} $(call libname,bin_mbn) ${CFLAGS} ${OBJ_MBN} $(LINK) $(LDFLAGS)
endif
