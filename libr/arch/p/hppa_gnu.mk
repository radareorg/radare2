OBJ_HPPA=p/hppa/plugin_gnu.o
OBJ_HPPA+=p/hppa/gnu/hppa-dis.o

STATIC_OBJ+=${OBJ_HPPA}
TARGET_HPPA=arch_hppa_gnu.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_HPPA}

${TARGET_HPPA}: ${OBJ_HPPA}
	${CC} $(call libname,arch_hppa) ${LDFLAGS} ${CFLAGS} -o arch_hppa_gnu.${EXT_SO} ${OBJ_HPPA}
endif
