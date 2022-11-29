OBJ_NULL=p/null/plugin.o

TARGET_NULL=arch_null.${EXT_SO}
STATIC_OBJ+=${OBJ_NULL}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_NULL}
${TARGET_NULL}: ${OBJ_NULL}
	${CC} $(call libname,arch_null) ${LDFLAGS} ${CFLAGS} -o ${TARGET_NULL} ${OBJ_NULL}
endif

