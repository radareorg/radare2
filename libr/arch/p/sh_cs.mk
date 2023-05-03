OBJ_SH_CS=p/sh_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_SH_CS}
TARGET_SH_CS=sh_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SH_CS}

${TARGET_SH_CS}: ${OBJ_SH_CS}
	${CC} ${CFLAGS} $(call libname,sh_cs) $(CS_CFLAGS) \
		-o sh_cs.${EXT_SO} ${OBJ_SH_CS} $(CS_LDFLAGS)
