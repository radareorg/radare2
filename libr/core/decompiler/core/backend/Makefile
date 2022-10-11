CORE_OBJ_DECOMP=back.o

STATIC_OBJ+=${CORE_OBJ_DECOMP}

CORE_OBJ_DECOMP=back.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_OBJ_DECOMP}

${CORE_OBJ_DECOMP}: ${CORE_OBJ_DECOMP}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o back.${EXT_SO} \
		$(SHLR)/sdb/src/libsdb.a \
		-L$(LIBR)/crypto -lr_crypto \
		${CORE_OBJ_DECOMP}
endif
