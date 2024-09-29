OBJ_M68K_CS=p/m68k_cs/plugin.o
# OBJ_M68K_CS+=p/m68k_cs/m68kass.o

include p/capstone.mk

STATIC_OBJ+=$(OBJ_M68K_CS)

TARGET_M68K_CS=m68k_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_M68K_CS}

${TARGET_M68K_CS}: ${OBJ_M68K_CS}
	${CC} ${CFLAGS} $(call libname,m68k_cs) $(CS_CFLAGS) \
		-o m68k_cs.${EXT_SO} ${OBJ_M68K_CS} $(CS_LDFLAGS)
