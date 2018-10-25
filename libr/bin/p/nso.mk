OBJ_NSO=bin_nso.o ../format/nxo/nxo.o
#include $(SHLR)/lz4/deps.mk

STATIC_OBJ+=${OBJ_NSO}
TARGET_NSO=bin_nso.${EXT_SO}

ALL_TARGETS+=${TARGET_NSO}

${TARGET_NSO}: ${OBJ_NSO}
	-${CC} $(call libname,bin_nso) ${CFLAGS} ${OBJ_NSO}
