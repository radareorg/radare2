/* radare - LGPL - Copyright 2010 nibble at develsec.org */
/* TODO:
 * - 64 bits support
 * - fcopyendian
 * Test:
 * gcc -Wall -I../../../include -L ../../../util -lr_util -DMAIN -DLIL_ENDIAN=1
 *     -DR_DEBUG=1 mach0.c -o mach0
 * ./mach0 <mach0 file> */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "mach0.h"
#include "mach0_specs.h"

static int r_bin_mach0_init_hdr(struct r_bin_mach0_obj_t* bin)
{
	lseek(bin->fd, 0, SEEK_SET);
	if (read(bin->fd, &bin->hdr, sizeof(struct mach_header)) != sizeof(struct mach_header)) {
		perror("read (hdr)");
		return R_FALSE;
	}
	if (bin->hdr.magic == MH_MAGIC)
		bin->endian = !LIL_ENDIAN;
	else if (bin->hdr.magic == MH_CIGAM)
		bin->endian = LIL_ENDIAN;
	else return R_FALSE;
	r_mem_copyendian((ut8*)&(bin->hdr.cputype), (ut8*)&(bin->hdr.cputype), sizeof(cpu_type_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->hdr.cpusubtype), (ut8*)&(bin->hdr.cpusubtype), sizeof(cpu_subtype_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->hdr.ncmds), (ut8*)&(bin->hdr.ncmds), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&bin->hdr.sizeofcmds, (ut8*)&bin->hdr.sizeofcmds, sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->hdr.flags), (ut8*)&(bin->hdr.flags), sizeof(uint32_t), !bin->endian);
	return R_TRUE;
}

static int r_bin_mach0_parse_seg(struct r_bin_mach0_obj_t* bin, ut64 off)
{
	int seg, i;

	seg = bin->nsegs - 1;
	if (!(bin->segs = realloc(bin->segs, bin->nsegs * sizeof(struct segment_command)))) {
		perror("realloc (seg)");
		return R_FALSE;
	}
	lseek(bin->fd, off, SEEK_SET);
	if (read(bin->fd, &bin->segs[seg], sizeof(struct segment_command))
			!= sizeof(struct segment_command)) {
		perror("read (seg)");
		return R_FALSE;
	}
	r_mem_copyendian((ut8*)&(bin->segs[seg].cmd), (ut8*)&(bin->segs[seg].cmd), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].cmdsize), (ut8*)&(bin->segs[seg].cmdsize), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].vmaddr), (ut8*)&(bin->segs[seg].vmaddr), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].vmsize), (ut8*)&(bin->segs[seg].vmsize), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].fileoff), (ut8*)&(bin->segs[seg].fileoff), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].filesize), (ut8*)&(bin->segs[seg].filesize), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].maxprot), (ut8*)&(bin->segs[seg].maxprot), sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].initprot), (ut8*)&(bin->segs[seg].initprot), sizeof(vm_prot_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].nsects), (ut8*)&(bin->segs[seg].nsects), sizeof(vm_prot_t), !bin->endian);
	r_mem_copyendian((ut8*)&(bin->segs[seg].flags), (ut8*)&(bin->segs[seg].flags), sizeof(uint32_t), !bin->endian);
	if (bin->segs[seg].nsects > 0) {
		bin->nsects += bin->segs[seg].nsects;
		if (!(bin->sects = realloc(bin->sects, bin->nsects * sizeof(struct section)))) {
			perror("realloc (sects)");
			return R_FALSE;
		}
		for (i = bin->nsects - bin->segs[seg].nsects; i < bin->nsects; i++) {
			if (read(bin->fd, &bin->sects[i], sizeof(struct section)) 
					!= sizeof(struct section)) {
				perror("read (sects)");
				return R_FALSE;
			}
			r_mem_copyendian((ut8*)&(bin->sects[i].addr), (ut8*)&(bin->sects[i].addr), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].size), (ut8*)&(bin->sects[i].size), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].offset), (ut8*)&(bin->sects[i].offset), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].align), (ut8*)&(bin->sects[i].align), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].reloff), (ut8*)&(bin->sects[i].reloff), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].nreloc), (ut8*)&(bin->sects[i].nreloc), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].flags), (ut8*)&(bin->sects[i].flags), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].reserved1), (ut8*)&(bin->sects[i].reserved1), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->sects[i].reserved2), (ut8*)&(bin->sects[i].reserved2), sizeof(uint32_t), !bin->endian);
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_parse_symtab(struct r_bin_mach0_obj_t* bin, ut64 off)
{
	struct symtab_command st;
	int i;

	lseek(bin->fd, off, SEEK_SET);
	if (read(bin->fd, &st, sizeof(struct symtab_command)) != sizeof(struct symtab_command)) {
		perror("read (symtab)");
		return R_FALSE;
	}
	r_mem_copyendian((ut8*)&st.cmd, (ut8*)&st.cmd, sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&st.cmdsize, (ut8*)&st.cmdsize, sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&st.symoff, (ut8*)&st.symoff, sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&st.nsyms, (ut8*)&st.nsyms, sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&st.stroff, (ut8*)&st.stroff, sizeof(uint32_t), !bin->endian);
	r_mem_copyendian((ut8*)&st.strsize, (ut8*)&st.strsize, sizeof(uint32_t), !bin->endian);
	if (st.strsize > 0 && st.strsize < bin->size && st.nsyms > 0) {
		bin->nsyms = st.nsyms;
		if (!(bin->symstr = malloc(st.strsize))) {
			perror("malloc (symstr)");
			return R_FALSE;
		}
		lseek(bin->fd, st.stroff, SEEK_SET);
		if (read(bin->fd, bin->symstr, st.strsize) != st.strsize) {
			perror("read (symstr)");
			return R_FALSE;
		}
		if (!(bin->symtab = malloc(st.nsyms * sizeof(struct nlist)))) {
			perror("malloc (symtab)");
			return R_FALSE;
		}
		lseek(bin->fd, st.symoff, SEEK_SET);
		for (i = 0; i < bin->nsyms; i++) {
			if (read(bin->fd, &bin->symtab[i], sizeof(struct nlist)) != sizeof(struct nlist)) {
				perror("read (nlist)");
				return R_FALSE;
			}
			r_mem_copyendian((ut8*)&bin->symtab[i].n_un, (ut8*)&bin->symtab[i].n_un, sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&bin->symtab[i].n_desc, (ut8*)&bin->symtab[i].n_desc, sizeof(uint16_t), !bin->endian);
			r_mem_copyendian((ut8*)&bin->symtab[i].n_value, (ut8*)&bin->symtab[i].n_value, sizeof(uint32_t), !bin->endian);
			IFDBG printf("sym: %s\n", bin->symstr+bin->symtab[i].n_un.n_strx);
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_init_items(struct r_bin_mach0_obj_t* bin)
{
	struct load_command lc = {0, 0};
	ut64 off;
	int i;

	for (i = 0, off = sizeof(struct mach_header); i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		lseek(bin->fd, off, SEEK_SET);
		if (read(bin->fd, &lc, sizeof(struct load_command)) != sizeof(struct load_command)) {
			perror("read (lc)");
			return R_FALSE;
		}
		r_mem_copyendian((ut8*)&lc.cmd, (ut8*)&lc.cmd, sizeof(uint32_t), !bin->endian);
		r_mem_copyendian((ut8*)&lc.cmdsize, (ut8*)&lc.cmdsize, sizeof(uint32_t), !bin->endian);
		IFDBG eprintf("cmd: 0x%02x  cmdsize= %i\n", lc.cmd, lc.cmdsize);
		switch (lc.cmd) {
		case LC_SEGMENT:
			bin->nsegs++;
			if (!r_bin_mach0_parse_seg(bin, off))
				return R_FALSE;
			break;
		case LC_SYMTAB:
			if (!r_bin_mach0_parse_symtab(bin, off))
				return R_FALSE;
			break;
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_init(struct r_bin_mach0_obj_t* bin)
{
	bin->segs = NULL;
	bin->nsegs = 0;
	bin->sects = NULL;
	bin->nsects = 0;
	bin->symtab = NULL;
	bin->symstr = NULL;
	bin->nsyms = 0;
	bin->size = lseek(bin->fd, 0, SEEK_END);
	if (!r_bin_mach0_init_hdr(bin)) {
		ERR("Warning: File is not MACH0\n");
		return R_FALSE;
	}
	if (!r_bin_mach0_init_items(bin))
		ERR("Warning: Cannot initalize items\n");
	return R_TRUE;
}

void* r_bin_mach0_free(struct r_bin_mach0_obj_t* bin)
{
	if (!bin)
		return NULL;
	if (bin->segs)
		free(bin->segs);
	if (bin->sects)
		free(bin->sects);
	if (bin->symtab)
		free(bin->symtab);
	if (bin->symstr)
		free(bin->symstr);
	close(bin->fd);
	free(bin);
	return NULL;
}

struct r_bin_mach0_obj_t* r_bin_mach0_new(const char* file)
{
	struct r_bin_mach0_obj_t *bin;
	if (!(bin = malloc(sizeof(struct r_bin_mach0_obj_t))))
		return NULL;
	if ((bin->fd = open(file, O_RDONLY)) == -1)
		return r_bin_mach0_free(bin);
	bin->file = file;
	if (!r_bin_mach0_init(bin))
		return r_bin_mach0_free(bin);
	return bin;
}

struct r_bin_mach0_section_t* r_bin_mach0_get_sections(struct r_bin_mach0_obj_t* bin)
{
	struct r_bin_mach0_section_t *sections;
	char segname[17], sectname[17];
	int i;
	if (!(sections = malloc(bin->nsects * sizeof(struct r_bin_mach0_section_t))))
		return NULL;
	for (i = 0; i < bin->nsects; i++) {
		sections[i].offset = (ut64)bin->sects[i].offset;
		sections[i].addr = (ut64)bin->sects[i].addr;
		sections[i].size = (ut64)bin->sects[i].size;
		sections[i].align = bin->sects[i].align;
		sections[i].flags = bin->sects[i].flags;;
		segname[16] = sectname[16] = '\0';
		memcpy(segname, bin->sects[i].segname, 16);
		memcpy(sectname, bin->sects[i].sectname, 16);
		snprintf(sections[i].name, MACH0_STRING_LENGTH, "%s:%s", segname, sectname);
	}
	return sections;
}

struct r_bin_mach0_symbol_t* r_bin_mach0_get_symbols(struct r_bin_mach0_obj_t* bin)
{
	return NULL;
}

#ifdef MAIN
int main(int argc, char *argv[])
{
	struct r_bin_mach0_obj_t *bin;
	struct r_bin_mach0_section_t *sections;
	struct r_bin_mach0_symbol_t *symbols;
	int i;

	if (argc != 2) {
		ERR("Usage: %s <mach0 file>\n", argv[0]);
		return 1;
	}
	if(!(bin = r_bin_mach0_new(argv[1]))) {
		ERR("Cannot open '%s'\n", argv[1]);
		return 1;
	}
	sections = r_bin_mach0_get_sections(bin);
	printf("-> SECTIONS\n");
	for (i = 0; sections && i < bin->nsects; i++)
		printf( "offset=0x%08llx address=0x%08llx size=%05lli name=%s\n",
				sections[i].offset, sections[i].addr, sections[i].size,
				sections[i].name);
	if (sections) free(sections);
	symbols = r_bin_mach0_get_symbols(bin);
	printf("-> SYMBOLS\n");
	for (i = 0; symbols && i < bin->nsyms; i++)
		printf( "offset=0x%08llx address=0x%08llx size=%05lli name=%s\n",
				symbols[i].offset, symbols[i].addr, symbols[i].size,
				symbols[i].name);
	if (symbols) free(symbols);
	r_bin_mach0_free(bin);

	return 0;
}
#endif
