OBJ_BF_PSEUDO+=$(LIBR)/arch/p/bf/pseudo.o

TARGET_BF_PSEUDO=parse_bf_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_BF_PSEUDO}
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_BF_PSEUDO}
${TARGET_BF_PSEUDO}: ${OBJ_BF_PSEUDO}
	${CC} $(call libname,parse_bf_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_BF_PSEUDO} ${OBJ_BF_PSEUDO}
endif
