OBJ_BPF_CS=p/bpf_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=$(OBJ_BPF_CS)
TARGET_BPF_CS=arch_bpf_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_BPF_CS}

${TARGET_BPF_CS}: ${OBJ_BPF_CS}
	${CC} ${CFLAGS} $(call libname,arch_bpf_cs) $(CS_CFLAGS) \
		-o arch_bpf_cs.${EXT_SO} ${OBJ_BPF_CS} $(CS_LDFLAGS)
