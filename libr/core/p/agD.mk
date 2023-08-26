CORE_OBJ_AGD=core_agD.o

STATIC_OBJ+=${CORE_OBJ_AGD}
CORE_TARGET_AGD=core_agD.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_AGD}

${CORE_TARGET_AGD}: ${CORE_OBJ_AGD}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o core_agD.${EXT_SO} \
		$(SHLR)/sdb/src/libsdb.a \
		-L$(LIBR)/crypto -lr_crypto \
		${CORE_OBJ_AGD}
endif
