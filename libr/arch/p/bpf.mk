OBJ_BPF=p/bpf/plugin.o

STATIC_OBJ+=${OBJ_BPF}
TARGET_BPF=arch_bpf.${EXT_SO}

ALL_TARGETS+=${TARGET_BPF}

${TARGET_BPF}: ${OBJ_BPF}
	${CC} $(call libname,arch_bpf) ${LDFLAGS} ${CFLAGS} -o arch_bpf.${EXT_SO} ${OBJ_BPF}
