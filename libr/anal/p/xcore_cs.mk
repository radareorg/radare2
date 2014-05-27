OBJ_XCORE_CS=anal_xcore_cs.o
CFLAGS+=-I../../shlr/capstone/include
STATIC_OBJ+=${OBJ_XCORE_CS}
SHARED_XCORE_CS=../../shlr/capstone/libcapstone.a

SHARED_OBJ+=${SHARED_XCORE_CS}
TARGET_XCORE_CS=anal_xcore_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_XCORE_CS}

${TARGET_XCORE_CS}: ${OBJ_XCORE_CS}
	${CC} ${CFLAGS} $(call libname,anal_xcore_cs) \
		-o anal_xcore_cs.${EXT_SO} ${OBJ_XCORE_CS}
