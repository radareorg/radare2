OBJ_SBPF_CS=p/sbpf_cs/plugin.o

include p/capstone.mk

STATIC_OBJ+=$(OBJ_SBPF_CS)
TARGET_SBPF_CS=arch_sbpf_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SBPF_CS}

${TARGET_SBPF_CS}: ${OBJ_SBPF_CS}
	${CC} ${CFLAGS} $(call libname,arch_sbpf_cs) $(CS_CFLAGS) \
		-o arch_sbpf_cs.${EXT_SO} ${OBJ_SBPF_CS} $(CS_LDFLAGS)