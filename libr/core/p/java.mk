CORE_OBJ_JAVA=core_java.o

#CORE_SHARED_JAVA=../../shlr/java/code.o
#CORE_SHARED_JAVA+=../../shlr/java/class.o
#CORE_SHARED_JAVA+=../../shlr/java/ops.o

CORE_SHARED2_JAVA=$(addprefix ../,${CORE_SHARED_JAVA})
CORE_OBJ_JAVA+=${CORE_SHARED2_JAVA}
CORE_SHARED2_JAVA=

STATIC_OBJ+=${CORE_OBJ_JAVA}
#SHARED_OBJ+=${CORE_OBJ_JAVA}
CORE_TARGET_JAVA=core_java.${EXT_SO}

ALL_TARGETS+=${CORE_TARGET_JAVA}

${CORE_TARGET_JAVA}: ${CORE_OBJ_JAVA}
	${CC} $(call libname,core_java) ${CFLAGS} \
		-o core_java.${EXT_SO} \
		$(SHLR)/java/libr_java.a \
		$(SHLR)/sdb/src/libsdb.a \
		${CORE_OBJ_JAVA} ${CORE_SHARED2_JAVA}
