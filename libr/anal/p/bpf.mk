OBJ_BPF=anal_bpf.o
BPF_ROOT=../asm/arch/bpf
CFLAGS+=-I$(BPF_ROOT)

STATIC_OBJ+=${OBJ_BPF}
TARGET_BPF=anal_bpf.${EXT_SO}

ALL_TARGETS+=${TARGET_BPF}

${TARGET_BPF}: ${OBJ_BPF}
	${CC} $(call libname,anal_bpf) ${LDFLAGS} ${CFLAGS} -o anal_bpf.${EXT_SO} ${OBJ_BPF}
