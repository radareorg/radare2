OBJ_JNI=anal_jni.o

STATIC_OBJ+=${OBJ_JNI}
TARGET_JNI=anal_jni.${EXT_SO}

ALL_TARGETS+=${TARGET_JNI}

${TARGET_JNI}: ${OBJ_JNI}
	${CC} $(call libname,anal_jni) ${LDFLAGS} \
		${CFLAGS} -o anal_jni.${EXT_SO} ${OBJ_JNI} \
		-L../../bin -lr_bin
