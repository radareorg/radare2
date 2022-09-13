OBJ_HPPA=anal_hppa_gnu.o
OBJ_HPPA+=../../asm/arch/hppa/gnu/hppa-dis.o

STATIC_OBJ+=${OBJ_HPPA}
TARGET_HPPA=anal_hppa_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_HPPA}

${TARGET_HPPA}: ${OBJ_HPPA}
	${CC} $(call libname,anal_hppa) ${LDFLAGS} ${CFLAGS} -o anal_hppa_gnu.${EXT_SO} ${OBJ_HPPA}
endif
