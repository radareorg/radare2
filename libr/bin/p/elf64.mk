OBJ_ELF64=bin_elf64.o bin_meta_elf64.o ../format/elf/elf64.o

STATIC_OBJ+=${OBJ_ELF64}
TARGET_ELF64=bin_elf64.${EXT_SO}

ALL_TARGETS+=${TARGET_ELF64}

${TARGET_ELF64}: ${OBJ_ELF64}
	${CC} ${CFLAGS} -o ${TARGET_ELF64} ${OBJ_ELF64}
	@#strip -s ${TARGET_ELF64}

