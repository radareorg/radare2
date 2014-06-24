OBJ_XCORE_CS=anal_xcore_cs.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_XCORE_CS}
TARGET_XCORE_CS=anal_xcore_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_XCORE_CS}

${TARGET_XCORE_CS}: ${OBJ_XCORE_CS}
	${CC} ${CFLAGS} $(call libname,anal_xcore_cs) $(CS_CFLAGS) \
		-o anal_xcore_cs.${EXT_SO} ${OBJ_XCORE_CS} $(CS_LDFLAGS)
