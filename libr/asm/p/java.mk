OBJ_JAVA_PSEUDO+=$(LIBR)/arch/p/java/pseudo.o

TARGET_JAVA_PSEUDO=parse_java_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_JAVA_PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_JAVA_PSEUDO}
${TARGET_JAVA_PSEUDO}: ${OBJ_JAVA_PSEUDO}
	${CC} $(call libname,parse_java_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_JAVA_PSEUDO} ${OBJ_JAVA_PSEUDO}
endif
