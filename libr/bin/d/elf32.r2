pfo elf_enums
pf.elf_ident [4]z[1]E[1]E[1]E.:: magic (elf_class)class (elf_data)data (elf_hdr_version)version
pf.elf_header ?[2]E[2]E[4]ExxxxN2N2N2N2N2N2 (elf_ident)ident (elf_type)type (elf_machine)machine (elf_obj_version)version entry phoff shoff flags ehsize phentsize phnum shentsize shnum shstrndx
pf.elf_phdr [4]Exxxxx[4]Ex (elf_p_type)type offset vaddr paddr filesz memsz (elf_p_flags)flags align
pf.elf_shdr x[4]E[4]Exxxxxxx name (elf_s_type)type (elf_s_flags_32)flags addr offset size link info addralign entsize
