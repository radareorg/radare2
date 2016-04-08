OBJ_M68K=anal_m68k.o

include ${CURDIR}capstone.mk

STATIC_OBJ+=${OBJ_M68K}
TARGET_M68K=anal_m68k.${EXT_SO}

ALL_TARGETS+=${TARGET_M68K}

${TARGET_M68K}: ${OBJ_M68K}
	${CC} $(call libname,anal_m68k) ${LDFLAGS} ${CFLAGS} -o anal_m68k.${EXT_SO} ${OBJ_M68K}
