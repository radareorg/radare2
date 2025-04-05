/* radare - MIT - Copyright 2025 - pancake */

// based on https://github.com/elliotnunn/pef2elf

#include <r_bin.h>
#include <r_lib.h>
#include <r_util.h>

#define PEF_MAGIC1 0x4A6F7921  // "Joy!"
#define PEF_MAGIC1_2 0x4a564d41 // "JVMA"
#define PEF_MAGIC2 0x70656666  // "peff"
#define PEF_MAX_SECTIONS 256

typedef struct {
	ut32 tag1;
	ut32 tag2;
	ut32 arch;
	ut32 version;
	ut32 timestamp;
	ut32 olddefvers;
	ut32 oldimpvers;
	ut32 currentvers;
	ut16 section_count;
	ut16 inst_section_count;
} __attribute__((packed)) PEFHeader;

typedef struct {
	ut32 name_offset;
	ut32 default_address;
	ut32 total_size;
	ut32 unpacked_size;
	ut32 packed_size;
	ut32 container_offset;
	ut8 kind;
	ut8 share_kind;
	ut8 alignment;
	ut8 reserved;
} __attribute__((packed)) PEFSectionHeader;

typedef struct {
	PEFHeader hdr;
	PEFSectionHeader *sections;
	ut16 section_count;
	ut8 *name_table;
	ut64 name_table_off;
	ut64 name_table_sz;
	ut32 entry_section;
	ut32 entry_offset;
	ut32 entry_phaddr;
	RList *libs;
	RList *imports;
} RBinPEFObj;

static RList *pef_libs(RBinFile *bf) {
	RBinPEFObj *obj = bf->bo->bin_obj;
	return obj->libs;
}

static RList *pef_imports(RBinFile *bf) {
	RBinPEFObj *obj = bf->bo->bin_obj;
	return obj->imports;
}

static bool pef_check(RBinFile *bf, RBuffer *b) {
	ut8 buf [8] = { 0 };
	if (r_buf_read_at (b, 0, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	ut32 magic1 = r_read_be32 (buf);
	ut32 magic2 = r_read_be32 (buf + 4);
	if (magic1 == PEF_MAGIC1 && magic2 == PEF_MAGIC2) {
		return true;
	}
	if (magic1 == PEF_MAGIC1_2 && magic2 == PEF_MAGIC2) {
		// unsure
		return true;
	}
	return false;
}

static bool pef_load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	PEFHeader hdr = { 0 };
	if (r_buf_read_at (b, 0, (ut8 *)&hdr, sizeof (PEFHeader)) != sizeof (PEFHeader)) {
		return false;
	}
#if 0
	if (r_read_be32 ((const ut8 *)&hdr.tag1) != PEF_MAGIC1 ||
	    r_read_be32 ((const ut8 *)&hdr.tag2) != PEF_MAGIC2) {
		return false;
	}
#endif
	RBinPEFObj *obj = R_NEW0 (RBinPEFObj);
	char arch[5] = { 0 };
	memcpy (arch, &hdr.arch, 4);
	if (!strcmp (arch, "pwpc")) {
		R_LOG_INFO ("arch: powerpc");
	} else {
		R_LOG_INFO ("arch %s", arch);
	}
	R_LOG_INFO ("version %d", r_read_be32 (&hdr.version));
	obj->hdr = hdr;
	int scount = r_read_be16 ((const ut8 *)&hdr.section_count);
	int iscount = r_read_be16 ((const ut8 *)&hdr.inst_section_count); // instantiated sections
	R_LOG_INFO ("%d %d", scount, iscount);
	obj->section_count = scount;
	obj->sections = (PEFSectionHeader *)calloc (scount, sizeof (PEFSectionHeader));
	if (!obj->sections) {
		r_free (obj);
		return false;
	}
	int i;
	ut64 shoff = 0x44; // sizeof (PEFHeader);
	for (i = 0; i < scount; i++) {
		PEFSectionHeader shdr;
		if (r_buf_read_at (b, shoff + i * sizeof (PEFSectionHeader), (ut8 *)&shdr, sizeof (PEFSectionHeader)) != sizeof (PEFSectionHeader)) {
			break;
		}
		memcpy (&obj->sections[i], &shdr, sizeof (PEFSectionHeader));
	}

	obj->entry_section = 0;
	obj->entry_offset = 0;
	for (i = 0; i < scount; i++) {
		R_LOG_INFO ("SCOUNT %d KIND %d", i, obj->sections[i].kind);
		if (obj->sections[i].kind == 4) { // loader section
			ut32 loader_offset = r_read_be32 ((const ut8 *)&obj->sections[i].container_offset);
			ut8 buf[8];
			if (r_buf_read_at (b, loader_offset, buf, sizeof (buf)) == sizeof (buf)) {
				obj->entry_section = r_read_be16 (buf);
				obj->entry_offset = r_read_be32 (buf + 4);
				obj->entry_phaddr = loader_offset + 4;
				// imports
				ut8 lbuf[128];
				r_buf_read_at (b, loader_offset, lbuf, sizeof (lbuf));
				ut32 libraries = r_read_be32 (lbuf + 24);
				eprintf ("libraries %d\n", libraries);
				ut32 imports = r_read_be32 (lbuf + 28);
				eprintf ("imports %d\n", imports);
				ut32 relocs = r_read_be32 (lbuf + 32);
				eprintf ("relocs %d\n", relocs);
				ut32 irelocs = r_read_be32 (lbuf + 36);
				eprintf ("irelocs %d\n", irelocs);
				ut32 strings = r_read_be32 (lbuf + 40);
				eprintf ("strings %d\n", strings);
				int j;
				obj->libs = r_list_newf (free);
				obj->imports = r_list_newf ((RListFree)r_bin_import_free);
				for (j = 0; j < libraries; j++) {
					ut32 libstruct = loader_offset + 56 + (24 * j);
					ut32 lname_offset = 0;
					r_buf_read_at (b, libstruct, (ut8*)&lname_offset, sizeof (lname_offset));
					// XXX dunno where this 128 comes from
					lname_offset = 128 + r_read_be32 (&lname_offset);
					char lname[128];
					lname[0] = 0;
					r_buf_read_at (b, strings + lname_offset, (ut8*)lname, sizeof (lname));
					R_LOG_DEBUG ("LIB %d @0x%08x = 0x%08x : %s", j, libstruct, lname_offset, lname);
					r_list_append (obj->libs, strdup (lname)); 
					// 
					ut32 first;
					ut32 count;
					r_buf_read_at (b, libstruct + 12, (ut8*)&count, sizeof (count));
					r_buf_read_at (b, libstruct + 16, (ut8*)&first, sizeof (first));
					count = r_read_be32 (&count);
					first = r_read_be32 (&first);
					R_LOG_INFO ("FIRST %d COUNT %d", first, count);
					int k;
					for (k = 0; k < count; k++) {
						// ut32 p = loader_offset + 56 + (24 * j) + (4 * k);
						ut32 p = loader_offset + 56 + (24 * libraries) + (4 * k);
						ut32 iname;
						r_buf_read_at (b, p, (ut8 *)&iname, sizeof (iname));
						iname = r_read_be32 (&iname) & 0xffffff;
						char sname[128];
						sname[0] = 0;
						r_buf_read_at (b, strings + 128 + iname, (ut8*)sname, sizeof (sname));
						RBinImport *bi = R_NEW0 (RBinImport);
						bi->name = r_bin_name_new (sname);
						bi->libname = strdup (lname);
						r_list_append (obj->imports, bi);// r_str_newf ("%s.%s", lname, sname));
						// eprintf ("--> %x %s\n", iname, sname);
					}
				}
			}
			break;
		}
	}
	bf->bo->bin_obj = obj;

	return true;
}

static void pef_free(RBinFile *bf) {
	RBinPEFObj *obj = bf->bo->bin_obj;
	if (obj) {
		r_free (obj->sections);
		r_free (obj);
	}
}

static RBinInfo *pef_get_info(RBinFile *bf) {
	RBinInfo *info = R_NEW0 (RBinInfo);
	info->file = bf->file ? strdup (bf->file) : NULL;
	info->arch = strdup ("ppc");
	info->bits = 32;
	info->big_endian = true;
	info->os = strdup ("macos");
	info->type = strdup ("pef");
	info->has_va = true;
	return info;
}

static int sort_by_paddr(const void *a, const void *b) {
	RBinSection *sa = (RBinSection *)a;
	RBinSection *sb = (RBinSection *)b;
	if (sa->paddr > sb->paddr) {
		return 1;
	}
	if (sa->paddr < sb->paddr) {
		return -1;
	}
	return 0;
}

static RList *pef_get_sections(RBinFile *bf) {
	RBinPEFObj *obj = bf->bo->bin_obj;
	RList *list = r_list_newf (free);
	if (!list || !obj || !obj->sections){
		 return NULL;
	}
	int i;
	for (i = 0; i < r_read_be16 ((const ut8 *)&obj->hdr.section_count); i++) {
		RBinSection *s = R_NEW0 (RBinSection);
		PEFSectionHeader *sec = &obj->sections[i];
		s->add = true;
		ut32 pa = r_read_be32 ((const ut8 *)&sec->container_offset);
		s->paddr = (pa && pa != UT32_MAX)? pa: 0;
		ut32 va = r_read_be32 ((const ut8 *)&sec->default_address);
		s->vaddr = (va && va != UT32_MAX)? va: s->paddr; // TODO + baddr
		ut32 sz = r_read_be32 ((const ut8 *)&sec->total_size);
		s->size = (sz && sz != UT32_MAX)? sz: 0;
		s->vsize = s->size;
		s->perm = R_PERM_R;
		switch (sec->kind) {
		case 0:
		case 4:
			s->perm |= R_PERM_X;
			break;
		case 1:
		case 6:
			s->perm |= R_PERM_W;
			break;
		}
		const char *share = "";

		switch (sec->share_kind) {
		case 1:
			share = "proc_";
			break;
		case 4:
			share = "global_";
			break;
		case 5:
			share = "protected_";
			break;
		}
		switch (sec->kind) {
		case 0:
			s->name = r_str_newf ("code_%s%d", share, i);
			break;
		case 1:
			s->name = r_str_newf ("data_%s%d", share, i);
			break;
		case 2:
			s->name = r_str_newf ("pidata_%s%d", share, i);
			break;
		case 3:
			s->name = r_str_newf ("rodata_%s%d", share, i);
			break;
		case 4:
			s->name = r_str_newf ("loader_%s%d", share, i);
			break;
		case 5:
			s->name = r_str_newf ("debug_%s%d", share, i);
			break;
		case 6:
			s->name = r_str_newf ("exedata_%s%d", share, i);
			break;
		case 7:
			s->name = r_str_newf ("exception_%s%d", share, i);
			break;
		case 8:
			s->name = r_str_newf ("traceback_%s%d", share, i);
			break;
		default:
			s->name = r_str_newf ("section_%s%d", share, i);
			break;
		}
		r_list_append (list, s);
	}
	RListIter *iter, *iter2;
	RBinSection *s, *s2;
	r_list_foreach (list, iter, s) {
		if (s->size != 0) {
			continue;
		}
		ut32 maxsz = 0;
		// fix boundaries
		r_list_foreach (list, iter2, s2) {
			// fix boundaries
			if (s2->paddr > s->paddr) {
				ut32 left = (s2->paddr - s->paddr);
				if (left > maxsz) {
					maxsz = left;
				}
			}
		}
		if (maxsz == 0) {
			maxsz = r_buf_size (bf->buf) - s->paddr;
		}
		s->size = maxsz;
		s->vsize = maxsz;
	}
#if 0
	RBinSection *hdrsec = R_NEW0 (RBinSection);
	hdrsec->name = strdup ("hdr_0");
	hdrsec->perm = R_PERM_R;
	hdrsec->paddr = 0;
	hdrsec->vaddr = 0;
	hdrsec->size = r_buf_size (bf->buf);
	hdrsec->vsize = hdrsec->size;
	hdrsec->add = true;
	r_list_prepend (list, hdrsec);
#endif
	r_list_sort (list, sort_by_paddr);
	return list;
}

static RList *pef_get_entries(RBinFile *bf) {
	RList *list = r_list_newf (free);
	RBinPEFObj *obj = bf->bo->bin_obj;
	if (!obj) {
		return list;
	}
	RBinAddr *entry = R_NEW0 (RBinAddr);
	ut32 es = obj->entry_section;
	if (es >= obj->section_count) {
		return list;
	}
	ut32 base = r_read_be32 ((const ut8 *)&obj->sections[es].default_address);
	if (base == UT32_MAX) {
		base = 0;
	}
	R_LOG_INFO ("baddr 0x%08x", base);
	R_LOG_INFO ("eoff %x", obj->entry_offset);
#if 0
	entry->paddr = r_read_be32 ((const ut8 *)&obj->sections[es].container_offset) + obj->entry_offset;
	entry->paddr += 4;
#endif
	entry->paddr = obj->entry_offset + 4;
	entry->vaddr = base + obj->entry_offset + 4;
	entry->hpaddr = obj->entry_phaddr;
	entry->hvaddr = obj->entry_phaddr;
	r_list_append (list, entry);
	return list;
}

#if 0
static RList *pef_get_symbols(RBinFile *bf) {
	// NOTE: actual export symbol table parsing should go here
	// for now, return empty list
	return r_list_newf (free);
}
#endif

RBinPlugin r_bin_plugin_pef = {
	.meta = {
		.name = "pef",
		.desc = "PEF (Preferred Executable Format) binary plugin",
		.license = "MIT",
	},
	.load = &pef_load,
	.check = &pef_check,
	.libs = pef_libs,
	.info = &pef_get_info,
.imports = &pef_imports,
	.sections = &pef_get_sections,
	.entries = &pef_get_entries,
//	.symbols = &pef_get_symbols,
	.destroy = &pef_free
};

#ifndef R2_PLUGIN_INCORE
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pef,
	.version = R2_VERSION
};
#endif
