OBJ_BPF_CS=anal_bpf_cs.o

include $(CURDIR)capstone.mk

STATIC_OBJ+=$(OBJ_BPF_CS)
TARGET_BPF_CS=anal_bpf_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_BPF_CS}

${TARGET_BPF_CS}: ${OBJ_BPF_CS}
	${CC} ${CFLAGS} $(call libname,anal_bpf_cs) $(CS_CFLAGS) \
		-o anal_bpf_cs.${EXT_SO} ${OBJ_BPF_CS} $(CS_LDFLAGS)
