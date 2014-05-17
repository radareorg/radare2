OBJ_SYSTEMZ_CS=anal_sysz.o
CFLAGS+=-I../../shlr/capstone/include
STATIC_OBJ+=${OBJ_SYSTEMZ_CS}
SHARED_SYSTEMZ_CS=../../shlr/capstone/libcapstone.a

SHARED_OBJ+=${SHARED_SYSTEMZ_CS}
TARGET_SYSTEMZ_CS=anal_sysz.${EXT_SO}

ALL_TARGETS+=${TARGET_SYSTEMZ_CS}

${TARGET_SYSTEMZ_CS}: ${OBJ_SYSTEMZ_CS}
	${CC} ${CFLAGS} $(call libname,anal_sysz) \
		-o anal_sysz.${EXT_SO} ${OBJ_SYSTEMZ_CS}
