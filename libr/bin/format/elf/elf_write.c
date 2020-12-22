/* radare - LGPL - Copyright 2010-2019 pancake, nibble */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

// XXX UGLY CODE
/* TODO: Take care of endianness */
/* TODO: Real error handling */
/* TODO: Resize sections before .init */
// ut64 Elf_(r_bin_elf_resize_section)(struct Elf_(r_bin_elf_obj_t) *bin, const char *name, ut64 size) {
ut64 Elf_(r_bin_elf_resize_section)(RBinFile *bf, const char *name, ut64 size) {
	struct Elf_(r_bin_elf_obj_t) *bin = bf->o->bin_obj; // , const char *name, ut64 size) {
	Elf_(Ehdr) *ehdr = &bin->ehdr;
	Elf_(Phdr) *phdr = bin->phdr, *phdrp;
	Elf_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *strtab = bin->shstrtab;
	ut8 *buf;
	ut64 off, got_offset = 0, got_addr = 0, rsz_offset = 0, delta = 0;
	ut64 rsz_osize = 0, rsz_size = size, rest_size = 0;
	int i, j, done = 0;

	if (size == 0) {
		eprintf ("0 size section?\n");
		return 0;
	}

	/* calculate delta */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		int idx = shdrp->sh_name;
		if (idx < 0 || idx >= bin->shstrtab_size) {
			continue;
		}
		const char *sh_name = &strtab[shdrp->sh_name];
		if (sh_name && !strncmp (name, sh_name, ELF_STRING_LENGTH)) {
			delta =  rsz_size - shdrp->sh_size;
			rsz_offset = (ut64)shdrp->sh_offset;
			rsz_osize = (ut64)shdrp->sh_size;
		}
	}

	if (delta == 0) {
		eprintf ("Cannot find section\n");
		return 0;
	}
 
	eprintf ("delta: %"PFMT64d"\n", delta);
	
	/* rewrite rel's (imports) */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp(&strtab[shdrp->sh_name], ".got")) {
			got_addr = (ut64)shdrp->sh_addr;
			got_offset = (ut64)shdrp->sh_offset;
		}
	}
	if (got_addr == 0 || got_offset == 0) {
		/* TODO: Unknown GOT address */
	}

	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strcmp (&strtab[shdrp->sh_name], ".rel.plt")) {
			Elf_(Rel) *rel, *relp;
			rel = (Elf_(Rel) *)malloc (1+shdrp->sh_size);
			if (!rel) {
				perror ("malloc");
				return 0;
			}
			if (r_buf_read_at (bin->b, shdrp->sh_offset, (ut8*)rel, shdrp->sh_size) == -1) {
				perror("read (rel)");
			}
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(Elf_(Rel)), relp++) {
				/* rewrite relp->r_offset */
				if (relp->r_offset - got_addr + got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;
					if (r_buf_write_at (bin->b, off, (ut8*)relp, sizeof (Elf_(Rel))) == -1) {
						perror("write (imports)");
					}
				}
			}
			free(rel);
			break;
		} else if (!strcmp (&strtab[shdrp->sh_name], ".rela.plt")) {
			Elf_(Rela) *rel, *relp;
			rel = (Elf_(Rela) *)malloc (shdrp->sh_size + 1);
			if (!rel) {
				perror("malloc");
				return 0;
			}
			if (r_buf_read_at (bin->b, shdrp->sh_offset, (ut8*)rel, shdrp->sh_size) == -1) {
				perror("read (rel)");
			}
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof(Elf_(Rela)), relp++) {
				/* rewrite relp->r_offset */
				if (relp->r_offset - got_addr + got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset+=delta;
					off = shdrp->sh_offset + j;
					if (r_buf_write_at (bin->b, off, (ut8*)relp, sizeof (Elf_(Rela))) == -1) {
						perror("write (imports)");
					}
				}
			}
			free(rel);
			break;
		}
	}

	/* rewrite section headers */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!done && !strncmp (name, &strtab[shdrp->sh_name], ELF_STRING_LENGTH)) {
			shdrp->sh_size = rsz_size;
			done = 1;
		} else if (shdrp->sh_offset >= rsz_offset + rsz_osize) {
			shdrp->sh_offset += delta;
			if (shdrp->sh_addr) {
				shdrp->sh_addr += delta;
			}
		}
		off = ehdr->e_shoff + i * sizeof (Elf_(Shdr));
		if (r_buf_write_at (bin->b, off, (ut8*)shdrp, sizeof (Elf_(Shdr))) == -1) {
			perror ("write (shdr)");
		}
		printf ("-> elf section (%s)\n", &strtab[shdrp->sh_name]);
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
			if (phdrp->p_vaddr) {
				phdrp->p_vaddr += delta;
			}
			if (phdrp->p_paddr) {
				phdrp->p_paddr += delta;
			}
		} else if (phdrp->p_offset + phdrp->p_filesz >= rsz_offset + rsz_osize) {
			phdrp->p_filesz += delta;
			phdrp->p_memsz += delta;
		} 
		off = ehdr->e_phoff + i * sizeof (Elf_(Phdr));
		if (r_buf_write_at (bin->b, off, (ut8 *)phdrp, sizeof (Elf_ (Phdr))) == -1) {
			perror ("write (phdr)");
		}
		printf ("-> program header (0x%08"PFMT64x")\n", (ut64) phdrp->p_offset);
	}

	/* rewrite other elf pointers (entrypoint, phoff, shoff) */
	if (ehdr->e_entry - bin->baddr >= rsz_offset + rsz_osize) {
		ehdr->e_entry += delta;
	}
	if (ehdr->e_phoff >= rsz_offset + rsz_osize) {
		ehdr->e_phoff += delta;
	}
	if (ehdr->e_shoff >= rsz_offset + rsz_osize) {
		ehdr->e_shoff += delta;
	}
	if (r_buf_write_at (bin->b, 0, (ut8*)ehdr, sizeof (Elf_(Ehdr))) == -1) {
		perror ("write (ehdr)");
	}

	/* inverse order to write bodies .. avoid overlapping here */
	/* XXX Check when delta is negative */
	rest_size = bin->size - (rsz_offset + rsz_osize);

	buf = (ut8 *)malloc (1+bin->size);
	r_buf_read_at (bin->b, 0, (ut8*)buf, bin->size);
	r_buf_set_bytes (bin->b, (ut8*)buf, (int)(rsz_offset+rsz_size+rest_size));

	printf ("COPY FROM 0x%08"PFMT64x"\n", (ut64)(rsz_offset+rsz_osize));
	r_buf_read_at (bin->b, rsz_offset + rsz_osize, (ut8*)buf, rest_size);
	printf ("COPY TO 0x%08"PFMT64x"\n", (ut64)(rsz_offset+rsz_size));
	r_buf_write_at (bin->b, rsz_offset + rsz_size, (ut8*)buf, rest_size);
	printf ("Shifted %d byte(s)\n", (int)delta);
	free (buf);
	bin->size = r_buf_size (bin->b);

	return delta;
}

/* XXX Endianness? */
bool Elf_(r_bin_elf_del_rpath)(RBinFile *bf) {
	struct Elf_(r_bin_elf_obj_t) *bin = bf->o->bin_obj;
	Elf_(Dyn) *dyn = NULL;
	ut64 stroff = 0LL;
	int ndyn, i, j;

	if (!bin->phdr) {
		return false;
	}
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type != PT_DYNAMIC) {
			continue;
		}
		if (!(dyn = malloc (bin->phdr[i].p_filesz + 1))) {
			perror ("malloc (dyn)");
			return false;
		}
		if (r_buf_read_at (bin->b, bin->phdr[i].p_offset, (ut8*)dyn, bin->phdr[i].p_filesz) == -1) {
			eprintf ("Error: read (dyn)\n");
			free (dyn);
			return false;
		}
		if ((ndyn = (int)(bin->phdr[i].p_filesz / sizeof (Elf_(Dyn)))) > 0) {
			for (j = 0; j < ndyn; j++) {
				if (dyn[j].d_tag == DT_STRTAB) {
					stroff = (ut64)(dyn[j].d_un.d_ptr - bin->baddr);
					break;
				}
			}
			for (j = 0; j < ndyn; j++) {
				if (dyn[j].d_tag == DT_RPATH || dyn[j].d_tag == DT_RUNPATH) {
					if (r_buf_write_at (bin->b, stroff + dyn[j].d_un.d_val,
								(ut8*)"", 1) == -1) {
						eprintf ("Error: write (rpath)\n");
						free (dyn);
						return false;
					}
				}
			}
		}
		free (dyn);
		break;
	}
	return true;
}

bool Elf_(r_bin_elf_section_perms)(RBinFile *bf, const char *name, int perms) {
	struct Elf_(r_bin_elf_obj_t) *bin = bf->o->bin_obj;
	Elf_(Ehdr) *ehdr = &bin->ehdr;
	Elf_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *strtab = bin->shstrtab;
	int i, patchoff;

	/* calculate delta */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		const char *shname = &strtab[shdrp->sh_name];
		int operms = shdrp->sh_flags;
		if (!strncmp (name, shname, ELF_STRING_LENGTH)) {
			ut8 newperms = (ut8)operms;
			// SHF_EXECINSTR
			if (perms & 1) {
				R_BIT_SET (&newperms, 2);
			} else {
				R_BIT_UNSET (&newperms, 2);
			}
			// SHF_WRITE
			if (perms & 2) {
				R_BIT_SET (&newperms, 0);
			} else {
				R_BIT_UNSET (&newperms, 0);
			}
			patchoff = bin->ehdr.e_shoff;
			patchoff += ((const ut8*)shdrp - (const ut8*)bin->shdr);
			patchoff += r_offsetof (Elf_(Shdr), sh_flags);
			printf ("wx %02x @ 0x%x\n", newperms, patchoff);
			r_buf_write_at (bf->buf, patchoff, (ut8*)&newperms, 1);
			return true;
		}
	}
	return false;
}

bool Elf_(r_bin_elf_entry_write)(RBinFile *bf, ut64 addr) {
	const int patchoff = 0x18;
#if R_BIN_ELF64
	printf ("wv8 0x%"PFMT64x" @ 0x%x\n", addr, patchoff);
	r_buf_write_at (bf->buf, patchoff, (ut8*)&addr, sizeof (addr));
#else
	ut32 addr32 = (ut32)addr;
	printf ("wv4 0x%x @ 0x%x\n", addr32, patchoff);
	r_buf_write_at (bf->buf, patchoff, (ut8*)&addr32, sizeof (addr32));
#endif
	return true;
}
