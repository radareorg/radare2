CORE_OBJ_A2F=core_a2f.o

STATIC_OBJ+=${CORE_OBJ_A2F}
CORE_TARGET_A2F=core_a2f.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_A2F}

${CORE_TARGET_A2F}: ${CORE_OBJ_A2F}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o core_a2f.${EXT_SO} \
		$(SHLR)/../subprojects/sdb/src/libsdb.a \
		-L$(LIBR)/muta -lr_muta \
		${CORE_OBJ_A2F}
endif
