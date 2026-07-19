CORE_OBJ_PSEUDO=pseudo/plugin.o pseudo/pseudo.o

STATIC_OBJ+=${CORE_OBJ_PSEUDO}
CORE_TARGET_PSEUDO=core_pseudo.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_PSEUDO}

${CORE_TARGET_PSEUDO}: ${CORE_OBJ_PSEUDO}
	${CC} $(call libname,core_pseudo) ${CFLAGS} \
		-o core_pseudo.${EXT_SO} \
		-L$(LIBR)/core -lr_core \
		${CORE_OBJ_PSEUDO}
endif
