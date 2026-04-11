CORE_OBJ_CALLARGS=core_callargs.o

STATIC_OBJ+=${CORE_OBJ_CALLARGS}
CORE_TARGET_CALLARGS=core_callargs.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_CALLARGS}

${CORE_TARGET_CALLARGS}: ${CORE_OBJ_CALLARGS}
	${CC} $(call libname,core_callargs) ${CFLAGS} \
		-o core_callargs.${EXT_SO} \
		-L$(LIBR)/core -lr_core \
		${CORE_OBJ_CALLARGS}
endif
