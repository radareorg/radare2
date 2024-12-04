OBJ_PICKLE_PSEUDO+=$(LIBR)/arch/p/pickle/pseudo.o

TARGET_PICKLE_PSEUDO=parse_pickle_pseudo.${EXT_SO}
ALL_TARGETS+=${TARGET_PICKLE_PSEUDO}
STATIC_OBJ+=${OBJ_PICKLE_PSEUDO}

${TARGET_PICKLE_PSEUDO}: ${OBJ_PICKLE_PSEUDO}
ifeq ($(CC),cccl)
	${CC} $(call libname,parse_pickle_pseudo) -L../../util -llibr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_PICKLE_PSEUDO} ${OBJ_PICKLE_PSEUDO}
else
	${CC} $(call libname,parse_pickle_pseudo) -L../../util -lr_util \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_PICKLE_PSEUDO} ${OBJ_PICKLE_PSEUDO}
endif
