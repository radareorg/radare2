CORE_OBJ_SIXREF=core_sixref.o

STATIC_OBJ+=${CORE_OBJ_SIXREF}
CORE_TARGET_SIXREF=core_sixref.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_SIXREF}

${CORE_TARGET_SIXREF}: ${CORE_OBJ_SIXREF}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o core_sixref.${EXT_SO} \
		$(SHLR)/sdb/src/libsdb.a \
		-L$(LIBR)/crypto -lr_crypto \
		${CORE_OBJ_SIXREF}
endif
