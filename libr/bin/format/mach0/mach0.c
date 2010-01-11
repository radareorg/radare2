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
	if (read(bin->fd, &bin->hdr, sizeof(struct mach_header))
		!= sizeof(struct mach_header)) {
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

static int r_bin_mach0_parse_seg(struct r_bin_mach0_obj_t* bin, int idx)
{
	int seg, i;

	seg = bin->nsegs - 1;
	if (!(bin->segs = realloc(bin->segs, bin->nsegs * sizeof(struct segment_command)))) {
		perror("realloc (seg)");
		return R_FALSE;
	}
	lseek(bin->fd, sizeof(struct mach_header) + idx, SEEK_SET);
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
		bin->nscns += bin->segs[seg].nsects;
		if (!(bin->scns = realloc(bin->scns, bin->nscns * sizeof(struct section)))) {
			perror("realloc (scns)");
			return R_FALSE;
		}
		for (i = bin->nscns - bin->segs[seg].nsects; i < bin->nscns; i++) {
			if (read(bin->fd, &bin->scns[i], sizeof(struct section)) 
					!= sizeof(struct section)) {
				perror("read (scns)");
				return R_FALSE;
			}
			r_mem_copyendian((ut8*)&(bin->scns[i].addr), (ut8*)&(bin->scns[i].addr), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].size), (ut8*)&(bin->scns[i].size), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].offset), (ut8*)&(bin->scns[i].offset), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].align), (ut8*)&(bin->scns[i].align), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].reloff), (ut8*)&(bin->scns[i].reloff), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].nreloc), (ut8*)&(bin->scns[i].nreloc), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].flags), (ut8*)&(bin->scns[i].flags), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].reserved1), (ut8*)&(bin->scns[i].reserved1), sizeof(uint32_t), !bin->endian);
			r_mem_copyendian((ut8*)&(bin->scns[i].reserved2), (ut8*)&(bin->scns[i].reserved2), sizeof(uint32_t), !bin->endian);
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_init_items(struct r_bin_mach0_obj_t* bin)
{
	struct load_command lc = {0, 0};
	int i, idx;

	for (i = 0, idx = 0; i < bin->hdr.ncmds; i++, idx += lc.cmdsize) {
		lseek(bin->fd, sizeof(struct mach_header) + idx, SEEK_SET);
		if (read(bin->fd, &lc, sizeof(struct load_command)) !=
			sizeof(struct load_command)) {
			perror("read (lc)");
			return R_FALSE;
		}
		r_mem_copyendian((ut8*)&lc.cmd, (ut8*)&lc.cmd, sizeof(uint32_t), !bin->endian);
		r_mem_copyendian((ut8*)&lc.cmdsize, (ut8*)&lc.cmdsize, sizeof(uint32_t), !bin->endian);
		switch (lc.cmd) {
		case LC_SEGMENT:
			bin->nsegs++;
			if (!r_bin_mach0_parse_seg(bin, idx))
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
	bin->scns = NULL;
	bin->nscns = 0;
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
	if (bin->scns)
		free(bin->scns);
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
	if (!r_bin_mach0_init(bin)) {
		r_bin_mach0_free(bin);
		return r_bin_mach0_free(bin);
	}
	return bin;
}

struct r_bin_mach0_section_t* r_bin_mach0_get_sections(struct r_bin_mach0_obj_t* bin)
{
	struct r_bin_mach0_section_t *sections;
	char segname[17], sectname[17];
	int i;
	if (!(sections = malloc(bin->nscns * sizeof(struct r_bin_mach0_section_t))))
		return NULL;
	for (i = 0; i < bin->nscns; i++) {
		sections[i].offset = (ut64)bin->scns[i].offset;
		sections[i].addr = (ut64)bin->scns[i].addr;
		sections[i].size = (ut64)bin->scns[i].size;
		sections[i].align = bin->scns[i].align;
		sections[i].flags = bin->scns[i].flags;;
		segname[16] = sectname[16] = '\0';
		memcpy(segname, bin->scns[i].segname, 16);
		memcpy(sectname, bin->scns[i].sectname, 16);
		snprintf(sections[i].name, MACH0_STRING_LENGTH, "%s:%s", segname, sectname);
	}
	return sections;
}

#ifdef MAIN
int main(int argc, char *argv[])
{
	struct r_bin_mach0_obj_t *bin;
	struct r_bin_mach0_section_t *sections;
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
	for (i = 0; sections && i < bin->nscns; i++)
		printf( "offset=0x%08llx address=0x%08llx size=%05lli name=%s\n",
				sections[i].offset, sections[i].addr, sections[i].size,
				sections[i].name);
	r_bin_mach0_free(bin);

	return 0;
}
#endif
