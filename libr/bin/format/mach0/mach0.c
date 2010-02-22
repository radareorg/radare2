/* radare - LGPL - Copyright 2010 nibble at develsec.org */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "mach0.h"

static int MACH0_(r_bin_mach0_init_hdr)(struct MACH0_(r_bin_mach0_obj_t)* bin)
{
	int magic, len;

	if (r_buf_read_at(bin->b, 0, (ut8*)&magic, 4) == -1) {
		eprintf("Error: read (magic)\n");
		return R_FALSE;
	}
	if (magic == MH_MAGIC)
		bin->endian = !LIL_ENDIAN;
	else if (magic == MH_CIGAM)
		bin->endian = LIL_ENDIAN;
	else return R_FALSE;
#if R_BIN_MACH064
	len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, bin->endian?"8I":"8i", 1);
#else
	len = r_buf_fread_at(bin->b, 0, (ut8*)&bin->hdr, bin->endian?"7I":"7i", 1);
#endif
	if (len == -1) {
		eprintf("Error: read (hdr)\n");
		return R_FALSE;
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_seg)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off)
{
	int seg, sect, len;

	seg = bin->nsegs - 1;
	if (!(bin->segs = realloc(bin->segs, bin->nsegs * sizeof(struct MACH0_(segment_command))))) {
		perror("realloc (seg)");
		return R_FALSE;
	}
#if R_BIN_MACH064
	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->segs[seg], bin->endian?"2I16c4L4I":"2i16c4l4i", 1);
#else
	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->segs[seg], bin->endian?"2I16c8I":"2i16c8i", 1);
#endif
	if (len == -1) {
		eprintf("Error: read (seg)\n");
		return R_FALSE;
	}
	if (bin->segs[seg].nsects > 0) {
		sect = bin->nsects;
		bin->nsects += bin->segs[seg].nsects;
		if (!(bin->sects = realloc(bin->sects, bin->nsects * sizeof(struct MACH0_(section))))) {
			perror("realloc (sects)");
			return R_FALSE;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at(bin->b, off + sizeof(struct MACH0_(segment_command)),
				(ut8*)&bin->sects[sect], bin->endian?"16c16c2L8I":"16c16c2l8i", bin->nsects - sect);
#else
		len = r_buf_fread_at(bin->b, off + sizeof(struct MACH0_(segment_command)),
				(ut8*)&bin->sects[sect], bin->endian?"16c16c9I":"16c16c9i", bin->nsects - sect);
#endif
		if (len == -1) {
			eprintf("Error: read (sects)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_symtab)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off)
{
	struct symtab_command st;
	int len;

	len = r_buf_fread_at(bin->b, off, (ut8*)&st, bin->endian?"6I":"6i", 1);
	if (len == -1) {
		eprintf("Error: read (symtab)\n");
		return R_FALSE;
	}
	if (st.strsize > 0 && st.strsize < bin->size && st.nsyms > 0) {
		bin->nsymtab = st.nsyms;
		if (!(bin->symstr = malloc(st.strsize))) {
			perror("malloc (symstr)");
			return R_FALSE;
		}
		if (r_buf_read_at(bin->b, st.stroff, (ut8*)bin->symstr, st.strsize) == -1) {
			eprintf("Error: read (symstr)\n");
			return R_FALSE;
		}
		if (!(bin->symtab = malloc(bin->nsymtab * sizeof(struct MACH0_(nlist))))) {
			perror("malloc (symtab)");
			return R_FALSE;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at(bin->b, st.symoff, (ut8*)bin->symtab, bin->endian?"I2cSL":"i2csl", bin->nsymtab);
#else
		len = r_buf_fread_at(bin->b, st.symoff, (ut8*)bin->symtab, bin->endian?"I2cSI":"i2csi", bin->nsymtab);
#endif
		if (len == -1) {
			eprintf("Error: read (nlist)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_dysymtab)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off)
{
	int len;

	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->dysymtab, bin->endian?"20I":"20i", 1);
	if (len == -1) {
		eprintf("Error: read (dysymtab)\n");
		return R_FALSE;
	}
	bin->ntoc = bin->dysymtab.ntoc;
	if (bin->ntoc > 0) {
		if (!(bin->toc = malloc(bin->ntoc * sizeof(struct dylib_table_of_contents)))) {
			perror("malloc (toc)");
			return R_FALSE;
		}
		len = r_buf_fread_at(bin->b, bin->dysymtab.tocoff, (ut8*)bin->toc, bin->endian?"2I":"2i", bin->ntoc);
		if (len == -1) {
			eprintf("Error: read (toc)\n");
			return R_FALSE;
		}
	}
	bin->nmodtab = bin->dysymtab.nmodtab;
	if (bin->nmodtab > 0) {
		if (!(bin->modtab = malloc(bin->nmodtab * sizeof(struct MACH0_(dylib_module))))) {
			perror("malloc (modtab)");
			return R_FALSE;
		}
#if R_BIN_MACH064
		len = r_buf_fread_at(bin->b, bin->dysymtab.modtaboff, (ut8*)bin->modtab, bin->endian?"12IL":"12il", bin->nmodtab);
#else
		len = r_buf_fread_at(bin->b, bin->dysymtab.modtaboff, (ut8*)bin->modtab, bin->endian?"13I":"13i", bin->nmodtab);
#endif
		if (len == -1) {
			eprintf("Error: read (modtab)\n");
			return R_FALSE;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_parse_thread)(struct MACH0_(r_bin_mach0_obj_t)* bin, ut64 off)
{
	int len;

	len = r_buf_fread_at(bin->b, off, (ut8*)&bin->thread, bin->endian?"2I":"2i", 1);
	if (len == -1) {
		eprintf("Error: read (thread)\n");
		return R_FALSE;
	}
#if 0
	eprintf ("%llx\n", off);
	eprintf ("cmd: %x\n", bin->thread.cmd);
	eprintf ("cmdsize: %x\n", bin->thread.cmdsize);
#endif
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_init_items)(struct MACH0_(r_bin_mach0_obj_t)* bin)
{
	struct load_command lc = {0, 0};
	ut64 off;
	int i, len;

	for (i = 0, off = sizeof(struct MACH0_(mach_header)); i < bin->hdr.ncmds; i++, off += lc.cmdsize) {
		len = r_buf_fread_at(bin->b, off, (ut8*)&lc, bin->endian?"2I":"2i", 1);
		if (len == -1) {
			eprintf("Error: read (lc)\n");
			return R_FALSE;
		}
		switch (lc.cmd) {
#if R_BIN_MACH064
		case LC_SEGMENT_64:
#else
		case LC_SEGMENT:
#endif
			bin->nsegs++;
			if (!MACH0_(r_bin_mach0_parse_seg)(bin, off))
				return R_FALSE;
			break;
		case LC_SYMTAB:
			if (!MACH0_(r_bin_mach0_parse_symtab)(bin, off))
				return R_FALSE;
			break;
		case LC_DYSYMTAB:
			if (!MACH0_(r_bin_mach0_parse_dysymtab)(bin, off))
				return R_FALSE;
			break;
		case LC_UNIXTHREAD:
		case LC_THREAD:
			if (!MACH0_(r_bin_mach0_parse_thread)(bin, off))
				return R_FALSE;
			break;
		}
	}
	return R_TRUE;
}

static int MACH0_(r_bin_mach0_init)(struct MACH0_(r_bin_mach0_obj_t)* bin)
{
	if (!MACH0_(r_bin_mach0_init_hdr)(bin)) {
		eprintf("Warning: File is not MACH0\n");
		return R_FALSE;
	}
	if (!MACH0_(r_bin_mach0_init_items)(bin))
		eprintf("Warning: Cannot initalize items\n");
	return R_TRUE;
}

void* MACH0_(r_bin_mach0_free)(struct MACH0_(r_bin_mach0_obj_t)* bin)
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

struct MACH0_(r_bin_mach0_obj_t)* MACH0_(r_bin_mach0_new)(const char* file)
{
	struct MACH0_(r_bin_mach0_obj_t) *bin;
	ut8 *buf;

	if (!(bin = malloc(sizeof(struct MACH0_(r_bin_mach0_obj_t)))))
		return NULL;
	memset (bin, 0, sizeof (struct MACH0_(r_bin_mach0_obj_t)));
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size))) 
		return MACH0_(r_bin_mach0_free)(bin);
	bin->b = r_buf_new();
	if (!r_buf_set_bytes(bin->b, buf, bin->size))
		return MACH0_(r_bin_mach0_free)(bin);
	free (buf);
	if (!MACH0_(r_bin_mach0_init)(bin))
		return MACH0_(r_bin_mach0_free)(bin);
	return bin;
}

struct r_bin_mach0_section_t* MACH0_(r_bin_mach0_get_sections)(struct MACH0_(r_bin_mach0_obj_t)* bin)
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

struct r_bin_mach0_symbol_t* MACH0_(r_bin_mach0_get_symbols)(struct MACH0_(r_bin_mach0_obj_t)* bin)
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

struct r_bin_mach0_import_t* MACH0_(r_bin_mach0_get_imports)(struct MACH0_(r_bin_mach0_obj_t)* bin)
{
	struct r_bin_mach0_import_t *imports;
	int i, j;

	if (!bin->symtab || !bin->symstr)
		return NULL;
	if (!(imports = malloc((bin->dysymtab.nundefsym + 1) * sizeof(struct r_bin_mach0_import_t))))
		return NULL;
	/* XXX: only iundefsym?  */
	for (i = bin->dysymtab.iundefsym, j = 0; j < bin->dysymtab.nundefsym; i++, j++) {
		imports[j].offset = bin->symtab[i].n_value; /* TODO */
		imports[j].addr = bin->symtab[i].n_value;
		strncpy(imports[j].name, (char*)bin->symstr+bin->symtab[i].n_un.n_strx, R_BIN_MACH0_STRING_LENGTH);
		imports[j].last = 0;
	}
	imports[j].last = 1;
	return imports;
}

struct r_bin_mach0_entrypoint_t* MACH0_(r_bin_mach0_get_entrypoints)(struct MACH0_(r_bin_mach0_obj_t)* bin)
{
	/* TODO */
	return NULL;
}

ut64 MACH0_(r_bin_mach0_get_baddr)(struct MACH0_(r_bin_mach0_obj_t)* bin)
{
	/* TODO */
	return UT64_MIN;
}
