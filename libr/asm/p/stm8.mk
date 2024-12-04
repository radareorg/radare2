OBJ_STM8PSEUDO+=$(LIBR)/arch/p/stm8/pseudo.o

TARGET_STM8PSEUDO=parse_stm8_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_STM8PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_STM8PSEUDO}
${TARGET_STM8PSEUDO}: ${OBJ_STM8PSEUDO}
	${CC} $(call libname,parse_stm8_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_STM8PSEUDO} ${OBJ_STM8PSEUDO}
endif
