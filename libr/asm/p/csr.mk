OBJ_CSR=asm_csr.o
OBJ_CSR+=../arch/csr/csr_disasm/dis.o

STATIC_OBJ+=${OBJ_CSR}
TARGET_CSR=asm_csr.so

ALL_TARGETS+=${TARGET_CSR}

${TARGET_CSR}: ${OBJ_CSR}
	${CC} ${CFLAGS} -o asm_csr.so ${OBJ_CSR}
	@#strip -s asm_x86.so
