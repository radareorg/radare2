OBJ_M680X_CS=p/m680x_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=$(OBJ_M680X_CS)

TARGET_M680X_CS=m680x_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_M680X_CS}

${TARGET_M680X_CS}: ${OBJ_M680X_CS}
	${CC} ${CFLAGS} $(call libname,m680x_cs) $(CS_CFLAGS) \
		-o m680x_cs.${EXT_SO} ${OBJ_M680X_CS} $(CS_LDFLAGS)
