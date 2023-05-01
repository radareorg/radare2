OBJ_XCORE_CS=p/xcore_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_XCORE_CS}
TARGET_XCORE_CS=xcore_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_XCORE_CS}

${TARGET_XCORE_CS}: ${OBJ_XCORE_CS}
	${CC} ${CFLAGS} $(call libname,xcore_cs) $(CS_CFLAGS) \
		-o xcore_cs.${EXT_SO} ${OBJ_XCORE_CS} $(CS_LDFLAGS)
