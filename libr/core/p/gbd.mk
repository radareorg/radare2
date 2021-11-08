CORE_OBJ_GBD=core_gbd.o

STATIC_OBJ+=${CORE_OBJ_GBD}
CORE_TARGET_GBD=core_gbd.${EXT_SO}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${CORE_TARGET_GBD}

${CORE_TARGET_GBD}: ${CORE_OBJ_GBD}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o core_gbd.${EXT_SO} \
		$(SHLR)/sdb/src/libsdb.a \
		-L$(LIBR)/crypto -lr_crypto \
		${CORE_OBJ_GBD}
endif
