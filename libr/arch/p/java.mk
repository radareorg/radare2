OBJ_JAVA=p/java/plugin.o

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,java) ${CFLAGS} \
		-o java.${EXT_SO} \
		${OBJ_JAVA} \
		$(SHLR)/java/libr_java.$(EXT_AR) \
		$(SHLR)/../subprojects/sdb/src/libsdb.$(EXT_AR)
