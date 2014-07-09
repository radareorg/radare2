OBJ_ELF64=bin_elf64.o bin_dbginfo_elf64.o bin_write_elf64.o
OBJ_ELF64+=../format/elf/elf64.o ../format/elf/elf64_write.o

STATIC_OBJ+=${OBJ_ELF64}
TARGET_ELF64=bin_elf64.${EXT_SO}

ALL_TARGETS+=${TARGET_ELF64}

${TARGET_ELF64}: ${OBJ_ELF64}
	-${CC} $(call libname,bin_elf64) -shared ${CFLAGS} \
	$(OBJ_ELF64) $(LINK) $(LDFLAGS)
