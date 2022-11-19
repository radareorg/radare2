OBJ_EVM_PSEUDO+=parse_evm_pseudo.o

TARGET_EVM_PSEUDO=parse_evm_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_EVM_PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_EVM_PSEUDO}
${TARGET_EVM_PSEUDO}: ${OBJ_EVM_PSEUDO}
	${CC} $(call libname,parse_evm_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_EVM_PSEUDO} ${OBJ_EVM_PSEUDO}
endif
