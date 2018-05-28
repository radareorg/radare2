OBJ_JAVA=bin_java.o 

SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})

STATIC_OBJ+=${OBJ_JAVA}
STATIC_OBJ+=${SHARED2_JAVA}

SHARED_OBJ+=${SHARED_JAVA}
TARGET_JAVA=bin_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,bin_java) ${CFLAGS} ${OBJ_JAVA} \
		$(LINK) $(LDFLAGS) ${SHARED2_JAVA} \
		${SHLR}/java/libr_java.${EXT_AR} \
		${SHLR}/sdb/src/libsdb.${EXT_AR}
