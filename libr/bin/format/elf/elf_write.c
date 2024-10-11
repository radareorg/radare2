/* radare - LGPL - Copyright 2010-2024 pancake, nibble */

#include <r_util.h>
#include "elf.h"

// XXX UGLY CODE
/* TODO: Take care of endianness */
/* TODO: Real error handling */
/* TODO: Resize sections before .init */
ut64 Elf_(resize_section)(RBinFile *bf, const char *name, ut64 size) {
	struct Elf_(obj_t) *bin = bf->bo->bin_obj; // , const char *name, ut64 size) {
	Elf_(Ehdr) *ehdr = &bin->ehdr;
	Elf_(Phdr) *phdr = bin->phdr, *phdrp;
	Elf_(Shdr) *shdr = bin->shdr, *shdrp;
	const char *strtab = bin->shstrtab;
	ut64 off, got_offset = 0, got_addr = 0, rsz_offset = 0, delta = 0;
	ut64 rsz_osize = 0, rsz_size = size, rest_size = 0;
	int i, j, done = 0;

	if (size == 0) {
		R_LOG_ERROR ("0 size section?");
		return 0;
	}
	bool section_not_found = true;

	/* calculate delta */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		int idx = shdrp->sh_name;
		if (idx < 0 || idx >= bin->shstrtab_size) {
			continue;
		}
		const char *sh_name = &strtab[shdrp->sh_name];
		if (sh_name && !strncmp (name, sh_name, ELF_STRING_LENGTH)) {
			section_not_found = false;
			if (shdrp->sh_type == 8) {
				// is virtual section. so we only need to patch the headers
				delta = 0;
				shdrp->sh_size = rsz_size;
				off = ehdr->e_shoff + (i * sizeof (Elf_(Shdr)));
				r_buf_write_at (bf->buf, off, (ut8*)shdrp, sizeof (Elf_(Shdr)));
				return 0;
			}
			delta = rsz_size - shdrp->sh_size;
			rsz_offset = (ut64)shdrp->sh_offset;
			rsz_osize = (ut64)shdrp->sh_size;
			break;
		}
	}

	if (section_not_found) {
		R_LOG_ERROR ("Cannot find section");
		return 0;
	}

	R_LOG_INFO ("File size delta: %"PFMT64d, delta);

	/* rewrite rel's (imports) */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strncmp (&strtab[shdrp->sh_name], ".got", ELF_STRING_LENGTH)) {
			got_addr = (ut64)shdrp->sh_addr;
			got_offset = (ut64)shdrp->sh_offset;
		}
	}
	if (got_addr == 0 || got_offset == 0) {
		/* TODO: Unknown GOT address */
	}

	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		if (!strncmp (&strtab[shdrp->sh_name], ".rel.plt", ELF_STRING_LENGTH)) {
			Elf_(Rel) *rel, *relp;
			rel = (Elf_(Rel) *)malloc (1 + shdrp->sh_size);
			if (!rel) {
				r_sys_perror ("malloc");
				return 0;
			}
			if (r_buf_read_at (bin->b, shdrp->sh_offset, (ut8*)rel, shdrp->sh_size) == -1) {
				r_sys_perror ("read (rel)");
			}
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof (Elf_(Rel)), relp++) {
				/* rewrite relp->r_offset */
				if (relp->r_offset - got_addr + got_offset >= rsz_offset + rsz_osize) {
					relp->r_offset += delta;
					off = shdrp->sh_offset + j;
					if (r_buf_write_at (bin->b, off, (ut8*)relp, sizeof (Elf_(Rel))) == -1) {
						r_sys_perror ("write (imports)");
					}
				}
			}
			free (rel);
			break;
		} else if (!strcmp (&strtab[shdrp->sh_name], ".rela.plt")) {
			Elf_(Rela) *rel, *relp;
			rel = (Elf_(Rela) *)malloc (shdrp->sh_size + 1);
			if (!rel) {
				r_sys_perror ("malloc");
				return 0;
			}
			if (r_buf_read_at (bin->b, shdrp->sh_offset, (ut8*)rel, shdrp->sh_size) == -1) {
				r_sys_perror ("read (rel)");
			}
			for (j = 0, relp = rel; j < shdrp->sh_size; j += sizeof (Elf_(Rela)), relp++) {
				/* rewrite relp->r_offset */
				if (relp->r_offset - got_addr + got_offset >= rsz_offset + rsz_osize) {
					off = shdrp->sh_offset + j;
					relp->r_offset += delta;
					if (r_buf_write_at (bin->b, off, (ut8*)relp, sizeof (Elf_(Rela))) == -1) {
						r_sys_perror ("write (imports)");
					}
				}
			}
			free (rel);
			break;
		}
	}

	/* rewrite section headers */
	for (i = 0, shdrp = shdr; i < ehdr->e_shnum; i++, shdrp++) {
		off = ehdr->e_shoff + (i * sizeof (Elf_(Shdr)));
		if (!done && !strncmp (name, strtab + shdrp->sh_name, ELF_STRING_LENGTH)) {
			R_LOG_INFO ("patching the virtual section size from %d to %d", shdrp->sh_size, rsz_size);
			Elf_(Shdr) *es = (Elf_(Shdr)*)shdrp;
			es->sh_size = rsz_size; // XXX this is tied to endian
			// r_write_le64 (&es->sh_size, rsz_size);
			r_buf_write_at (bf->buf, off , (ut8*)shdrp, sizeof (Elf_(Shdr)));
			done = true;
		} else if (shdrp->sh_offset >= rsz_offset + rsz_osize) {
			shdrp->sh_offset += delta;
			if (shdrp->sh_addr) {
				shdrp->sh_addr += delta;
			}
		}
#if 1
		R_LOG_INFO ("patching write");
#if 0
		r_buf_write_at (bf->buf, off, (ut8*)&shdrp, sizeof (Elf_(Shdr)));
#else
		// TODO: write to bf->buf if the final bin needs to be patched
		if (r_buf_write_at (bin->b, off, (ut8*)shdrp, sizeof (Elf_(Shdr))) == -1) {
			r_sys_perror ("write (shdr)");
		}
#endif
#endif
		R_LOG_DEBUG ("-> elf section (%s)", strtab + shdrp->sh_name);
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
			r_sys_perror ("write (phdr)");
		}
		printf ("-> program header (0x%08"PFMT64x")\n", (ut64) phdrp->p_offset);
	}

	/* rewrite other elf pointers (entrypoint, phoff, shoff) */
	if (ehdr->e_entry - bin->baddr >= rsz_offset + rsz_osize) {
		ehdr->e_entry += delta;
		R_LOG_INFO ("patch entry");
	}
	if (ehdr->e_phoff >= rsz_offset + rsz_osize) {
		ehdr->e_phoff += delta;
		R_LOG_INFO ("patch phoff");
	}
	if (ehdr->e_shoff >= rsz_offset + rsz_osize) {
		ehdr->e_shoff += delta;
		R_LOG_INFO ("patch shoff");
	}
	R_LOG_INFO ("writing ehdr");
	if (r_buf_write_at (bin->b, 0, (ut8*)ehdr, sizeof (Elf_(Ehdr))) == -1) {
		r_sys_perror ("write (ehdr)");
	}

	/* Inverse order to write bodies to avoid overlapping */
	/* XXX Check when delta is negative */
	rest_size = bin->size - (rsz_offset + rsz_osize);

	if (delta == 0) {
		R_LOG_INFO ("Size unchanged");
	} else {
		ut8 *buf = (ut8 *)malloc (1 + bin->size);
		if (!buf) {
			R_LOG_ERROR ("Cannot allocate %d", bin->size);
			return 0;
		}
		r_buf_read_at (bin->b, 0, (ut8*)buf, bin->size);
		r_buf_set_bytes (bin->b, (ut8*)buf, (int)(rsz_offset + rsz_size + rest_size));
		printf ("COPY FROM 0x%08"PFMT64x"\n", (ut64)(rsz_offset + rsz_osize));
		r_buf_read_at (bin->b, rsz_offset + rsz_osize, (ut8*)buf, rest_size);
		printf ("COPY TO 0x%08"PFMT64x"\n", (ut64)(rsz_offset + rsz_size));
		r_buf_write_at (bin->b, rsz_offset + rsz_size, (ut8*)buf, rest_size);
		printf ("Shifted %d byte(s)\n", (int)delta);
		bin->size = r_buf_size (bin->b);
		free (buf);
	}

	return delta;
}

/* XXX Endianness? */
bool Elf_(del_rpath)(RBinFile *bf) {
	struct Elf_(obj_t) *bin = bf->bo->bin_obj;
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
			r_sys_perror ("malloc (dyn)");
			return false;
		}
		if (r_buf_read_at (bin->b, bin->phdr[i].p_offset, (ut8*)dyn, bin->phdr[i].p_filesz) == -1) {
			R_LOG_ERROR ("read (dyn)");
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
						R_LOG_ERROR ("write (rpath)");
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

bool Elf_(section_perms)(RBinFile *bf, const char *name, int perms) {
	struct Elf_(obj_t) *bin = bf->bo->bin_obj;
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

bool Elf_(entry_write)(RBinFile *bf, ut64 addr) {
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
