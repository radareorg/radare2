OBJ_BPF_PSEUDO+=parse_bpf_pseudo.o

TARGET_BPF_PSEUDO=parse_bpf_pseudo.${EXT_SO}
STATIC_OBJ+=${OBJ_BPF_PSEUDO}
ifeq ($(CC),cccl)
LIBDEPS=-L../../util -llibr_util
LIBDEPS+=-L../../flag -llibr_flag
else
LIBDEPS=-L../../util -lr_util
LIBDEPS+=-L../../flag -lr_flag
endif

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_BPF_PSEUDO}
${TARGET_BPF_PSEUDO}: ${OBJ_BPF_PSEUDO}
	${CC} $(call libname,parse_bpf_pseudo) ${LIBDEPS} $(LDFLAGS) \
		$(LDFLAGS_SHARED) ${CFLAGS} -o ${TARGET_BPF_PSEUDO} ${OBJ_BPF_PSEUDO}
endif
