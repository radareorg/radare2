OBJ_XALZ=bin_xalz.o

STATIC_OBJ+=${OBJ_XALZ}
TARGET_XALZ=bin_xalz.${EXT_SO}

ALL_TARGETS+=${TARGET_XALZ}

${TARGET_XALZ}: ${OBJ_XALZ}
	-${CC} $(call libname,bin_xalz) ${CFLAGS} ${OBJ_XALZ}
