OBJ_JAVA=anal_java.o
SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})

OBJ_JAVA+=${SHARED2_JAVA}

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=anal_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,anal_java) ${CFLAGS} \
		-o anal_java.${EXT_SO} \
		${OBJ_JAVA} ${SHARED2_JAVA} \
		$(SHLR)/java/libr_java.$(EXT_AR) \
		$(SHLR)/sdb/src/libsdb.$(EXT_AR)
