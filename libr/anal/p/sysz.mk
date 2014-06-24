OBJ_SYSTEMZ_CS=anal_sysz.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_SYSTEMZ_CS}

TARGET_SYSTEMZ_CS=anal_sysz.${EXT_SO}

ALL_TARGETS+=${TARGET_SYSTEMZ_CS}

${TARGET_SYSTEMZ_CS}: ${OBJ_SYSTEMZ_CS}
	${CC} ${CFLAGS} $(call libname,anal_sysz) $(CS_LDFLAGS) \
		-o anal_sysz.${EXT_SO} ${OBJ_SYSTEMZ_CS}
