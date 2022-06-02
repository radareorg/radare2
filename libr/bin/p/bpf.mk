OBJ_BPF=bin_bpf.o

STATIC_OBJ+=${OBJ_BPF}
TARGET_BPF=bin_bpf.${EXT_SO}

ALL_TARGETS+=${TARGET_BPF}

${TARGET_BPF}: ${OBJ_BPF}
	${CC} $(call libname,bin_bpf) $(DL_LIBS) ${CFLAGS} $(OBJ_BPF) $(LINK) $(LDFLAGS) \
	-L../../magic -lr_magic \
	-L../../util -lr_util
