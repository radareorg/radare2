OBJ_CSR=anal_csr.o

STATIC_OBJ+=${OBJ_CSR}
TARGET_CSR=anal_csr.${EXT_SO}

ALL_TARGETS+=${TARGET_CSR}

${TARGET_CSR}: ${OBJ_CSR}
	${CC} ${CFLAGS} -o anal_csr.${EXT_SO} ${OBJ_CSR}
	@#strip -s anal_csr.${EXT_SO}
