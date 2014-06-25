OBJ_JAVA=anal_java.o
##SHARED_JAVA+=../../shlr/java/ops.o
#SHARED_JAVA+=../../shlr/java/code.o
#SHARED_JAVA+=../../shlr/java/class.o
SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})
OBJ_JAVA+=${SHARED2_JAVA}

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=anal_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,anal_java) ${CFLAGS} \
		-o anal_java.${EXT_SO} \
		${OBJ_JAVA} ${SHARED2_JAVA} \
		$(SHLR)/java/libr_java.a \
		$(SHLR)/sdb/src/libsdb.a
