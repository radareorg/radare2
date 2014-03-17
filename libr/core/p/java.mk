OBJ_JAVA=core_java.o
SHARED_JAVA+=../../shlr/java/code.o
SHARED_JAVA+=../../shlr/java/class.o
SHARED_JAVA+=../../shlr/java/ops.o
SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})
OBJ_JAVA+=${SHARED2_JAVA}
#SHARED2_JAVA=

STATIC_OBJ+=${OBJ_JAVA}
TARGET_JAVA=core_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA}
	${CC} $(call libname,core_java) ${CFLAGS} \
		-o core_java.${EXT_SO} \
		${OBJ_JAVA} ${SHARED2_JAVA}
