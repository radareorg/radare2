OBJ_ELF=bin_elf.o bin_meta_elf.o bin_write_elf.o
OBJ_ELF+=../format/elf/elf.o ../format/elf/elf_write.o

STATIC_OBJ+=${OBJ_ELF}
TARGET_ELF=bin_elf.${EXT_SO}

ALL_TARGETS+=${TARGET_ELF}

${TARGET_ELF}: ${OBJ_ELF}
	${CC} ${CFLAGS} -o ${TARGET_ELF} ${OBJ_ELF}
	@#strip -s ${TARGET_ELF}
