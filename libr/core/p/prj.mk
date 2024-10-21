CORE_OBJ_PRJ=core_prj.o

STATIC_OBJ+=${CORE_OBJ_PRJ}
CORE_TARGET_PRJ=core_prj.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_PRJ}

${CORE_TARGET_PRJ}: ${CORE_OBJ_PRJ}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o core_prj.${EXT_SO} \
		-L$(LIBR)/core -lr_core \
		${CORE_OBJ_PRJ}
endif
