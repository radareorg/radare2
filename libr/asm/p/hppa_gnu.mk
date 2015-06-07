OBJ_HPPA=asm_hppa_gnu.o
OBJ_HPPA+=../arch/hppa/gnu/hppa-dis.o

STATIC_OBJ+=${OBJ_HPPA}
TARGET_HPPA=asm_hppa_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_HPPA}

${TARGET_HPPA}: ${OBJ_HPPA}
	${CC} $(call libname,asm_hppa) ${LDFLAGS} ${CFLAGS} -o asm_hppa_gnu.${EXT_SO} ${OBJ_HPPA}
endif
