OBJ_JAVA=bin_java.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=bin_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,bin_java) ${CFLAGS} ${OBJ_JAVA} \
		$(LINK) $(LDFLAGS) \
		${SHLR}/java/libr_java.${EXT_AR} \
		${SHLR}/../subprojects/sdb/src/libsdb.${EXT_AR}
