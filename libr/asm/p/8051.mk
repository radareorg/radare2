OBJ_8051PSEUDO+=$(LIBR)/arch/p/8051/pseudo.o

TARGET_8051PSEUDO=parse_8051_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_8051PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_8051PSEUDO}
${TARGET_8051PSEUDO}: ${OBJ_8051PSEUDO}
	${CC} $(call libname,parse_8051_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_8051PSEUDO} ${OBJ_8051PSEUDO}
endif