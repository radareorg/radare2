/* radare - LGPL - Copyright 2010 nibble<.ds@gmail.com> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

// XXX UGLY CODE
/* TODO: Take care of endianess */
/* TODO: Real error handling */
/* TODO: Resize sections before .init */
ut64 Elf_(r_bin_elf_resize_section)(struct Elf_(r_bin_elf_obj_t) *bin, const char *name, ut64 size) {
	Elf_(Ehdr) *ehdr = &bin->ehdr;
	Elf_(Phdr) *phdr = bin->phdr, *phdrp;
	Elf_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *strtab = bin->strtab;
	ut8 *buf;
	ut64 off, got_offset, got_addr = 0, rsz_offset, delta = 0;
	ut64 rsz_osize = 0, rsz_size = size, rest_size = 0;
	int i, j, done = 0;

	if (size == 0) {
		printf("0 size section?\n");
		return 0;
	}

	/* calculate delta */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) 
		if (!strncmp(name, &strtab[shdrp->sh_name], ELF_STRING_LENGTH)) {
			delta =  rsz_size - shdrp->sh_size;
			rsz_offset = (ut64)shdrp->sh_offset;
			rsz_osize = (ut64)shdrp->sh_size;
		}

	if (delta == 0) {
		printf("Cannot find section\n");
		return 0;
	}
 
	printf("delta: %lld\n", delta);
	
	/* rewrite rel's (imports) */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&strtab[shdrp->sh_name], ".got"))
			got_addr = (ut64)shdrp->sh_offset;
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
				return 0;
			}
			if (r_buf_read_at(bin->b, shdrp->sh_offset, (ut8*)rel, shdrp->sh_size) == -1)
				perror("read (rel)");

			got_offset = (rel->r_offset - bin->baddr - got_addr) & ELF_GOTOFF_MASK;
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(Elf_(Rel)), relp++) {
				r_mem_copyendian((ut8*)&(relp->r_offset), (ut8*)&(relp->r_offset),
						sizeof(Elf_(Addr)), !bin->endian);
				/* rewrite relp->r_offset */
				if (relp->r_offset - bin->baddr - got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;
					if (r_buf_write_at (bin->b, off, (ut8*)relp, sizeof (Elf_(Rel))) == -1)
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
				return 0;
			}

			if (r_buf_read_at(bin->b, shdrp->sh_offset, (ut8*)rel, shdrp->sh_size) == -1)
				perror("read (rel)");

			got_offset = (rel->r_offset - bin->baddr - got_addr) & ELF_GOTOFF_MASK;
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(Elf_(Rela)), relp++) {
				r_mem_copyendian((ut8*)&(relp->r_offset), (ut8*)&(relp->r_offset),
						sizeof(Elf_(Addr)), !bin->endian);
				/* rewrite relp->r_offset */
				if (relp->r_offset - bin->baddr - got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;

					if (r_buf_write_at (bin->b, off, (ut8*)relp, sizeof (Elf_(Rela))) == -1)
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
		if (r_buf_write_at (bin->b, off, (ut8*)shdrp, sizeof (Elf_(Shdr))) == -1)
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
		if (r_buf_write_at (bin->b, off, (ut8*)phdrp, sizeof (Elf_(Phdr))) == -1)
			perror("write (phdr)");
		printf("-> program header (%08llx)\n", (ut64) phdrp->p_offset);
	}

	/* rewrite other elf pointers (entrypoint, phoff, shoff) */
	if (ehdr->e_entry - bin->baddr >= rsz_offset + rsz_osize)
		ehdr->e_entry += delta;
	if (ehdr->e_phoff >= rsz_offset + rsz_osize)
		ehdr->e_phoff += delta;
	if (ehdr->e_shoff >= rsz_offset + rsz_osize)
		ehdr->e_shoff += delta;
	if (r_buf_write_at (bin->b, 0, (ut8*)ehdr, sizeof (Elf_(Ehdr))) == -1)
		perror("write (ehdr)");

	/* inverse order to write bodies .. avoid overlapping here */
	/* XXX Check when delta is negative */
	rest_size = bin->size - (rsz_offset + rsz_osize);

	buf = (ut8 *)malloc (bin->size);
	r_buf_read_at (bin->b, 0, (ut8*)buf, bin->size);
	r_buf_set_bytes (bin->b, (ut8*)buf, (int)(rsz_offset+rsz_size+rest_size));

	printf("COPY FROM 0x%08llx\n", (ut64)(rsz_offset+rsz_osize));
	r_buf_read_at (bin->b, rsz_offset+rsz_osize, (ut8*)buf, rest_size);
	printf("COPY TO 0x%08llx\n", (ut64)(rsz_offset+rsz_size));
	r_buf_write_at (bin->b, rsz_offset+rsz_size, (ut8*)buf, rest_size);
	printf("Shifted %d bytes\n", (int)delta);
	free(buf);
	bin->size = bin->b->length;

	return delta;
}

/* XXX Endianness? */
int Elf_(r_bin_elf_del_rpath)(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *dyn = NULL;
	ut64 stroff;
	int ndyn, i, j;

	for (i = 0; i < bin->ehdr.e_phnum; i++)
		if (bin->phdr[i].p_type == PT_DYNAMIC) {
			if (!(dyn = malloc (bin->phdr[i].p_filesz))) {
				perror("malloc (dyn)");
				return R_FALSE;
			}
			if (r_buf_read_at (bin->b, bin->phdr[i].p_offset, (ut8*)dyn, bin->phdr[i].p_filesz) == -1) {
				eprintf("Error: read (dyn)\n");
				free (dyn);
				return R_FALSE;
			}
			ndyn = (int)(bin->phdr[i].p_filesz / sizeof(Elf_(Dyn)));
			for (j = 0; j < ndyn; j++)
				if (dyn[j].d_tag == DT_STRTAB) {
					stroff = (ut64)(dyn[j].d_un.d_ptr - bin->baddr);
					break;
				}
			for (j = 0; j < ndyn; j++)
				if (dyn[j].d_tag == DT_RPATH || dyn[j].d_tag == DT_RUNPATH) {
					if (r_buf_write_at (bin->b, stroff + dyn[j].d_un.d_val,
								(ut8*)"", 1) == -1) {
						eprintf("Error: write (rpath)\n");
						free (dyn);
						return R_FALSE;
					}
				}
			free (dyn);
			break;
		}
	return R_TRUE;
}
