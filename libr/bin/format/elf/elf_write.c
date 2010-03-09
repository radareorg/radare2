/* radare - LGPL - Copyright 2010 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

#if 0 
/* TODO: Take care of endianess */
/* TODO: Real error handling */
/* TODO: Resize sections before .init */
u64 Elf_(r_bin_elf_resize_section)(struct Elf_(r_bin_elf_obj_t) *bin, const char *name, u64 size)
{
	Elf_(Ehdr) *ehdr = &bin->ehdr;
	Elf_(Phdr) *phdr = bin->phdr, *phdrp;
	Elf_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *strtab = bin->strtab;
	u8 *buf;
	u64 off, got_offset, got_addr = 0, rsz_offset, delta = 0;
	u64 rsz_osize = 0, rsz_fsize, rsz_size = size, rest_size = 0;
	int i, j, done = 0;

	if (size == 0) {
		printf("0 size section?\n");
		return 0;
	}
	rsz_fsize = lseek(bin->fd, 0, SEEK_END);

	/* calculate delta */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) 
		if (!strncmp(name, &strtab[shdrp->sh_name], ELF_STRING_LENGTH)) {
			delta =  rsz_size - shdrp->sh_size;
			rsz_offset = (u64)shdrp->sh_offset;
			rsz_osize = (u64)shdrp->sh_size;
		}

	if (delta == 0) {
		printf("Cannot find section\n");
		return 0;
	}
 
	printf("delta: %lld\n", delta);
	
	/* rewrite rel's (imports) */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&strtab[shdrp->sh_name], ".got"))
			got_addr = (u64)shdrp->sh_offset;
	}
	if (got_addr == 0) {
		/* TODO: Unknown GOT address */
	}

	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&strtab[shdrp->sh_name], ".rel.plt")) {
			Elf_(Rel) *rel, *relp;
			rel = (Elf_(Rel) *)malloc(shdrp->sh_size);
			if (rel == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) < 0)
				perror("lseek");
			if (read(bin->fd, rel, shdrp->sh_size) != shdrp->sh_size)
				perror("read");

			got_offset = (rel->r_offset - bin->baddr - got_addr) & ELF_GOTOFF_MASK;
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(Elf_(Rel)), relp++) {
				r_mem_copyendian((u8*)&(relp->r_offset), sizeof(Elf_(Addr)), !bin->endian);
				/* rewrite relp->r_offset */
				if (relp->r_offset - bin->baddr - got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;

					if (lseek(bin->fd, off, SEEK_SET) < 0)
						perror("lseek");
					if (write(bin->fd, &relp, sizeof(Elf_(Rel))) != sizeof(Elf_(Rel)))
						perror("write (imports)");
				}
			}
			free(rel);
			break;
		} else if (!strcmp(&strtab[shdrp->sh_name], ".rela.plt")) {
			Elf_(Rela) *rel, *relp;
			rel = (Elf_(Rela) *)malloc(shdrp->sh_size);
			if (rel == NULL) {
				perror("malloc");
				return -1;
			}

			if (lseek(bin->fd, shdrp->sh_offset, SEEK_SET) < 0)
				perror("lseek");
			if (read(bin->fd, rel, shdrp->sh_size) != shdrp->sh_size)
				perror("read");

			got_offset = (rel->r_offset - bin->baddr - got_addr) & ELF_GOTOFF_MASK;
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(Elf_(Rela)), relp++) {
				r_mem_copyendian((u8*)&(relp->r_offset), sizeof(Elf_(Addr)), !bin->endian);
				/* rewrite relp->r_offset */
				if (relp->r_offset - bin->baddr - got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;

					if (lseek(bin->fd, off, SEEK_SET) < 0)
						perror("lseek");
					if (write(bin->fd, &relp, sizeof(Elf_(Rela))) != sizeof(Elf_(Rela)))
						perror("write (imports)");
				}
			}
			free(rel);
			break;
		}
	}

	/* rewrite section headers */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!done && !strncmp(name, &strtab[shdrp->sh_name], ELF_STRING_LENGTH)) {
			shdrp->sh_size = rsz_size;
			done = 1;
		} else if (shdrp->sh_offset >= rsz_offset + rsz_osize) {
			shdrp->sh_offset += delta;
			if (shdrp->sh_addr) shdrp->sh_addr += delta;

		}
		off = ehdr->e_shoff + i * sizeof(Elf_(Shdr));
		if (lseek(bin->fd, off, SEEK_SET) < 0)
			perror("lseek");
		if (write(bin->fd, shdrp, sizeof(Elf_(Shdr))) != sizeof(Elf_(Shdr)))
			perror("write (shdr)");
		printf("-> elf section (%s)\n", &strtab[shdrp->sh_name]);
	}

	/* rewrite program headers */
	for (i = 0, phdrp = phdr; i < ehdr->e_phnum; i++, phdrp++) {
#if 0 
		if (phdrp->p_offset < rsz_offset && phdrp->p_offset + phdrp->p_filesz > rsz_offset) {
			phdrp->p_filesz += delta;
			phdrp->p_memsz += delta;
		}
#endif 
		if (phdrp->p_offset >= rsz_offset + rsz_osize) {
			phdrp->p_offset += delta;
			if (phdrp->p_vaddr) phdrp->p_vaddr += delta;
			if (phdrp->p_paddr) phdrp->p_paddr += delta;
		}
		off = ehdr->e_phoff + i * sizeof(Elf_(Phdr));
		if (lseek(bin->fd, off, SEEK_SET) < 0)
			perror("lseek");
		if (write(bin->fd, phdrp, sizeof(Elf_(Phdr))) != sizeof(Elf_(Phdr)))
			perror("write (phdr)");
		printf("-> program header (%08llx)\n", (u64) phdrp->p_offset);
	}

	/* rewrite other elf pointers (entrypoint, phoff, shoff) */
	if (ehdr->e_entry - bin->baddr >= rsz_offset + rsz_osize)
		ehdr->e_entry += delta;
	if (ehdr->e_phoff >= rsz_offset + rsz_osize)
		ehdr->e_phoff += delta;
	if (ehdr->e_shoff >= rsz_offset + rsz_osize)
		ehdr->e_shoff += delta;
	if (lseek(bin->fd, 0, SEEK_SET) < 0)
		perror("lseek");
	if (write(bin->fd, ehdr, sizeof(Elf_(Ehdr))) != sizeof(Elf_(Ehdr)))
		perror("write (ehdr)");

	/* inverse order to write bodies .. avoid overlapping here */
	/* XXX Check when delta is negative */
	rest_size = rsz_fsize - (rsz_offset + rsz_osize);
	buf = (u8 *)malloc(rest_size);
	printf("COPY FROM 0x%08llx\n", (u64) rsz_offset+rsz_osize);
	lseek(bin->fd, rsz_offset+rsz_osize, SEEK_SET);
	read(bin->fd, buf, rest_size);

	printf("COPY TO 0x%08llx\n", (u64) rsz_offset+rsz_size);
	lseek(bin->fd, rsz_offset+rsz_size, SEEK_SET);
	write(bin->fd, buf, rest_size);
	printf("Shifted %d bytes\n", (int)delta);
	free(buf);

	/* Reinit structs*/
	Elf_(r_bin_elf_init)(bin);

	return delta;
}
#endif

