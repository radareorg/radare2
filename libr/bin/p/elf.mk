OBJ_ELF=bin_elf.o ../format/elf/elf.o

STATIC_OBJ+=${OBJ_ELF}
TARGET_ELF=bin_elf.so

ALL_TARGETS+=${TARGET_ELF}

${TARGET_ELF}: ${OBJ_ELF}
	${CC} ${CFLAGS} -o ${TARGET_ELF} ${OBJ_ELF}
	@#strip -s ${TARGET_ELF}

