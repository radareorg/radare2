CORE_OBJ_ANAL=core_anal.o

STATIC_OBJ+=${CORE_OBJ_ANAL}
CORE_TARGET_ANAL=core_anal.${EXT_SO}

ALL_TARGETS+=${CORE_TARGET_ANAL}

${CORE_TARGET_ANAL}: ${CORE_OBJ_ANAL}
	${CC} $(call libname,core_anal) ${CFLAGS} \
		-o core_anal.${EXT_SO} \
		$(SHLR)/sdb/src/libsdb.a \
		${CORE_OBJ_ANAL}
