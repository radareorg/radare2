OBJ_PYC_PSEUDO+=$(LIBR)/arch/p/pyc/pseudo.o

TARGET_PYC_PSEUDO=parse_pyc_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_PYC_PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_PYC_PSEUDO}
${TARGET_PYC_PSEUDO}: ${OBJ_PYC_PSEUDO}
	${CC} $(call libname,parse_pyc_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_PYC_PSEUDO} ${OBJ_PYC_PSEUDO}
endif
