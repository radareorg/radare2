OBJ_NULL=bin_null.o

STATIC_OBJ+=${OBJ_NULL}
TARGET_NULL=bin_null.${EXT_SO}

ALL_TARGETS+=${TARGET_NULL}

include $(SHLR)/zip/deps.mk

${TARGET_NULL}: ${OBJ_NULL}
ifeq ($(CC),cccl)
	${CC} $(call libname,bin_null) $(DL_LIBS) ${CFLAGS} $(OBJ_NULL) $(LINK) $(LDFLAGS) \
	-L../../util -llibr_util
else
	${CC} $(call libname,bin_null) $(DL_LIBS) ${CFLAGS} $(OBJ_NULL) $(LINK) $(LDFLAGS) \
	-L../../util -lr_util
endif
