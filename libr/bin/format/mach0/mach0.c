/* radare - LGPL - Copyright 2010 nibble at develsec.org */
/* TODO:
 * - 64 bits support
 * - fcopyendian
 * Test:
 * gcc -Wall -I../../../include -L ../../../util -lr_util -DMAIN -DLIL_ENDIAN=1
 *     -DR_DEBUG=1 mach0.c -o mach0
 * ./mach0 <mach0 file> */

#include <stdio.h>
#include <fcntl.h>
#include <r_types.h>
#include <r_util.h>
#include "mach0.h"
#include "mach0_specs.h"

static int r_bin_mach0_init_hdr(struct r_bin_mach0_obj_t* bin)
{
	int len, magic;
	if (r_buf_read_at(bin->b, 0, (ut8*)&magic, 4) == -1) {
		ERR("Error: read (magic)\n");
		return R_FALSE;
	}
	if (magic == MH_MAGIC)
		bin->endian = !LIL_ENDIAN;
	else if (magic == MH_CIGAM)
		bin->endian = LIL_ENDIAN;
	else return R_FALSE;
	if (bin->endian)
		len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, "7I", 1);
	else
		len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, "7i", 1);
	if (len == -1) {
		ERR("Error: read (hdr)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int r_bin_mach0_parse_seg(struct r_bin_mach0_obj_t* bin, ut64 off)
{
	int seg, sect, len;

	seg = bin->nsegs - 1;
	if (!(bin->segs = realloc(bin->segs, bin->nsegs * sizeof(struct segment_command)))) {
		perror("realloc (seg)");
		return R_FALSE;
	}
	if (bin->endian)
		len = r_buf_fread_at(bin->b, off, (ut8*)&bin->segs[seg], "2I16c8I", 1);
	else
		len = r_buf_fread_at(bin->b, off, (ut8*)&bin->segs[seg], "2i16c8i", 1);
	if (len == -1) {
		ERR("Error: read (seg)\n");
		return R_FALSE;
	}
	if (bin->segs[seg].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[seg].nsects;
		if (!(bin->sects = realloc(bin->sects, bin->nsects * sizeof(struct section)))) {
			perror("realloc (sects)");
			return R_FALSE;
		}
		if (bin->endian)
			len = r_buf_fread_at(bin->b, off + sizeof(struct segment_command),
					(ut8*)&bin->sects[sect], "16c16c9I", bin->nsects - sect);
		else
			len = r_buf_fread_at(bin->b, off + sizeof(struct segment_command),
					(ut8*)&bin->sects[sect], "16c16c9i", bin->nsects - sect);
		if (len == -1) {
			ERR("Error: read (sects)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_parse_symtab(struct r_bin_mach0_obj_t* bin, ut64 off)
{
	struct symtab_command st;
	int len;

	if (bin->endian)
		len = r_buf_fread_at(bin->b, off, (ut8*)&st, "6I", 1);
	else
		len = r_buf_fread_at(bin->b, off, (ut8*)&st, "6i", 1);
	if (len == -1) {
		ERR("Error: read (symtab)\n");
		return R_FALSE;
	}
	if (st.strsize > 0 && st.strsize < bin->size && st.nsyms > 0) {
		bin->nsymtab = st.nsyms;
		if (!(bin->symstr = malloc(st.strsize))) {
			perror("malloc (symstr)");
			return R_FALSE;
		}
		if (r_buf_read_at(bin->b, st.stroff, (ut8*)bin->symstr, st.strsize) == -1) {
			ERR("Error: read (symstr)\n");
			return R_FALSE;
		}
		if (!(bin->symtab = malloc(bin->nsymtab * sizeof(struct nlist)))) {
			perror("malloc (symtab)");
			return R_FALSE;
		}
		if (bin->endian)
			len = r_buf_fread_at(bin->b, st.symoff, (ut8*)bin->symtab, "I2cSI", bin->nsymtab);
		else
			len = r_buf_fread_at(bin->b, st.symoff, (ut8*)bin->symtab, "i2csi", bin->nsymtab);
		if (len == -1) {
			ERR("Error: read (nlist)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_parse_dysymtab(struct r_bin_mach0_obj_t* bin, ut64 off)
{
	int len;

	if (bin->endian)
		len = r_buf_fread_at(bin->b, off, (ut8*)&bin->dysymtab, "20I", 1);
	else
		len = r_buf_fread_at(bin->b, off, (ut8*)&bin->dysymtab, "20i", 1);
	if (len == -1) {
		ERR("Error: read (dysymtab)\n");
		return R_FALSE;
	}
	bin->ntoc = bin->dysymtab.ntoc;
	if (bin->ntoc > 0) {
		if (!(bin->toc = malloc(bin->ntoc * sizeof(struct dylib_table_of_contents)))) {
			perror("malloc (toc)");
			return R_FALSE;
		}
		if (bin->endian)
			len = r_buf_fread_at(bin->b, bin->dysymtab.tocoff, (ut8*)bin->toc, "2I", bin->ntoc);
		else
			len = r_buf_fread_at(bin->b, bin->dysymtab.tocoff, (ut8*)bin->toc, "2i", bin->ntoc);
		if (len == -1) {
			ERR("Error: read (toc)\n");
			return R_FALSE;
		}
	}
	bin->nmodtab = bin->dysymtab.nmodtab;
	if (bin->nmodtab > 0) {
		if (!(bin->modtab = malloc(bin->nmodtab * sizeof(struct dylib_module)))) {
			perror("malloc (modtab)");
			return R_FALSE;
		}
		if (bin->endian)
			len = r_buf_fread_at(bin->b, bin->dysymtab.modtaboff, (ut8*)bin->modtab, "13I", bin->nmodtab);
		else
			len = r_buf_fread_at(bin->b, bin->dysymtab.modtaboff, (ut8*)bin->modtab, "13i", bin->nmodtab);
		if (len == -1) {
			ERR("Error: read (modtab)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int r_bin_mach0_init_items(struct r_bin_mach0_obj_t* bin)
{
	struct load_command lc = {0, 0};
	ut64 off;
	int i, len;

	for (i = 0, off = sizeof(struct mach_header); i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		if (bin->endian)
			len = r_buf_fread_at(bin->b, off, (ut8*)&lc, "2I", 1);
		else
			len = r_buf_fread_at(bin->b, off, (ut8*)&lc, "2i", 1);
		if (len == -1) {
			ERR("Error: read (lc)\n");
			return R_FALSE;
		}
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
		case LC_DYSYMTAB:
			if (!r_bin_mach0_parse_dysymtab(bin, off))
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
	bin->nsymtab = 0;
	bin->toc = NULL;
	bin->ntoc = 0;
	bin->modtab = NULL;
	bin->nmodtab = 0;
	bin->baddr = 0;
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
	if (bin->toc)
		free(bin->toc);
	if (bin->modtab)
		free(bin->modtab);
	if (bin->b)
		r_buf_free(bin->b);
	free(bin);
	return NULL;
}

struct r_bin_mach0_obj_t* r_bin_mach0_new(const char* file)
{
	struct r_bin_mach0_obj_t *bin;
	ut8 *buf;
	if (!(bin = malloc(sizeof(struct r_bin_mach0_obj_t))))
		return NULL;
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) 
		return r_bin_mach0_free(bin);
	bin->b = r_buf_new();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return r_bin_mach0_free(bin);
	free (buf);
	if (!r_bin_mach0_init(bin))
		return r_bin_mach0_free(bin);
	return bin;
}

struct r_bin_mach0_section_t* r_bin_mach0_get_sections(struct r_bin_mach0_obj_t* bin)
{
	struct r_bin_mach0_section_t *sections;
	char segname[17], sectname[17];
	int i;

	if (!bin->sects)
		return NULL;
	if (!(sections = malloc((bin->nsects + 1) * sizeof(struct r_bin_mach0_section_t))))
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
		snprintf(sections[i].name, R_BIN_MACH0_STRING_LENGTH, "%s:%s", segname, sectname);
		sections[i].last = 0;
	}
	sections[i].last = 1;
	return sections;
}

struct r_bin_mach0_symbol_t* r_bin_mach0_get_symbols(struct r_bin_mach0_obj_t* bin)
{
	struct r_bin_mach0_symbol_t *symbols;
	int i, j;

	if (!bin->symtab || !bin->symstr)
		return NULL;
	if (!(symbols = malloc((bin->dysymtab.nextdefsym + 1) * sizeof(struct r_bin_mach0_symbol_t))))
		return NULL;
	/* XXX: only extdefsym? */
	for (i = bin->dysymtab.iextdefsym, j = 0; j < bin->dysymtab.nextdefsym; i++, j++) {
		symbols[j].offset = bin->symtab[i].n_value;
		symbols[j].addr = bin->symtab[i].n_value; /* TODO: baddr? */
		symbols[j].size = 0; /* TODO: Is it anywhere? */
		strncpy(symbols[j].name, (char*)bin->symstr+bin->symtab[i].n_un.n_strx, R_BIN_MACH0_STRING_LENGTH);
		symbols[j].last = 0;
	}
	symbols[j].last = 1;
	return symbols;
}

struct r_bin_mach0_import_t* r_bin_mach0_get_imports(struct r_bin_mach0_obj_t* bin)
{
	struct r_bin_mach0_import_t *imports;
	int i, j;

	if (!bin->symtab || !bin->symstr)
		return NULL;
	if (!(imports = malloc((bin->dysymtab.nundefsym + 1) * sizeof(struct r_bin_mach0_import_t))))
		return NULL;
	/* XXX: only iundefsym?  */
	for (i = bin->dysymtab.iundefsym, j = 0; j < bin->dysymtab.nundefsym; i++, j++) {
		imports[j].offset = bin->symtab[i].n_value;
		imports[j].addr = bin->symtab[i].n_value;
		strncpy(imports[j].name, (char*)bin->symstr+bin->symtab[i].n_un.n_strx, R_BIN_MACH0_STRING_LENGTH);
		imports[j].last = 0;
	}
	imports[j].last = 1;
	return imports;
}

struct r_bin_mach0_entrypoint_t* r_bin_mach0_get_entrypoints(struct r_bin_mach0_obj_t* bin)
{
	return NULL;
}

ut64 r_bin_mach0_get_baddr(struct r_bin_mach0_obj_t* bin)
{
	return UT64_MIN;
}
