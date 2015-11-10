OBJ_ANY=bin_any.o

STATIC_OBJ+=${OBJ_ANY}
TARGET_ANY=bin_any.${EXT_SO}

ALL_TARGETS+=${TARGET_ANY}

include $(SHLR)/zip/deps.mk

${TARGET_ANY}: ${OBJ_ANY}
	${CC} $(call libname,bin_any) $(DL_LIBS) ${CFLAGS} $(OBJ_ANY) $(LINK) $(LDFLAGS) \
	-L../../magic -lr_magic \
	-L../../util -lr_util
