OBJ_JAVA=asm_java.o

SHARED2_JAVA=$(addprefix ../,${SHARED_JAVA})

STATIC_OBJ+=${OBJ_JAVA}
SHARED_OBJ+=${SHARED_JAVA}
TARGET_JAVA=asm_java.${EXT_SO}

ALL_TARGETS+=${TARGET_JAVA}

${TARGET_JAVA}: ${OBJ_JAVA} ${SHARED2_JAVA}
	${CC} $(call libname,asm_java) ${LDFLAGS} ${CFLAGS} \
		-o asm_java.${EXT_SO} ${OBJ_JAVA} ${SHARED2_JAVA} \
		$(SHLR)/java/libr_java.a \
		$(SHLR)/sdb/src/libsdb.a
