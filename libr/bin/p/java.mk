OBJ_JAVA=bin_java.o 

SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})

STATIC_OBJ+=${OBJ_JAVA}
ifeq ($(WITHNONPIC),1)
STATIC_OBJ+=${SHARED2_JAVA}
endif

SHARED_OBJ+=${SHARED_JAVA}
TARGET_JAVA=bin_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,bin_java) ${CFLAGS} ${OBJ_JAVA} \
		$(LINK) $(LDFLAGS) ${SHARED2_JAVA} \
		${SHLR}/java/libr_java.a \
		${SHLR}/sdb/src/libsdb.a
