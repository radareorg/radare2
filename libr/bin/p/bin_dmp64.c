/* radare2 - LGPL - Copyright 2020-2024 - abcSup */

#include <r_bin.h>
#include "dmp/dmp64.h"

static Sdb *get_sdb(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->bo->bin_obj;
	return (obj && obj->kv) ? obj->kv: NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_dmp64_free ((struct r_bin_dmp64_obj_t*)bf->bo->bin_obj);
}

static char *header(RBinFile *bf, int mode) {
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->bo->bin_obj;
	RStrBuf *sb = r_strbuf_new ("");
#define p(f,...) r_strbuf_appendf (sb, f, ##__VA_ARGS__)
	p ("DUMP_HEADER64:\n");
	p ("  MajorVersion : 0x%08"PFMT32x"\n", obj->header->MajorVersion);
	p ("  MinorVersion : 0x%08"PFMT32x"\n", obj->header->MinorVersion);
	p ("  DirectoryTableBase : 0x%016"PFMT64x"\n", obj->header->DirectoryTableBase);
	p ("  PfnDataBase : 0x%016"PFMT64x"\n", obj->header->PfnDataBase);
	p ("  PsLoadedModuleList : 0x%016"PFMT64x"\n", obj->header->PsLoadedModuleList);
	p ("  PsActiveProcessHead : 0x%016"PFMT64x"\n", obj->header->PsActiveProcessHead);
	p ("  MachineImageType : 0x%08"PFMT32x"\n", obj->header->MachineImageType);
	p ("  NumberProcessors : 0x%08"PFMT32x"\n", obj->header->NumberProcessors);
	p ("  BugCheckCode : 0x%08"PFMT32x"\n", obj->header->BugCheckCode);
	p ("  BugCheckParameter1 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[0]);
	p ("  BugCheckParameter2 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[1]);
	p ("  BugCheckParameter3 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[2]);
	p ("  BugCheckParameter4 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[3]);
	p ("  KdDebuggerDataBlock : 0x%016"PFMT64x"\n", obj->header->KdDebuggerDataBlock);
	p ("  SecondaryDataState : 0x%08"PFMT32x"\n", obj->header->SecondaryDataState);
	p ("  ProductType : 0x%08"PFMT32x"\n", obj->header->ProductType);
	p ("  SuiteMask : 0x%08"PFMT32x"\n", obj->header->SuiteMask);
	if (obj->bmp_header) {
		p ("\nBITMAP_DUMP:\n");
		p ("  HeaderSize : 0x%08"PFMT64x"\n", obj->bmp_header->FirstPage);
		p ("  BitmapSize : 0x%08"PFMT64x"\n", obj->bmp_header->Pages);
		p ("  Pages : 0x%08"PFMT64x"\n", obj->bmp_header->TotalPresentPages);
	}
#undef p
	return r_strbuf_drain (sb);
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->bo->bin_obj;

	ret->arch = strdup ("x86");
	ret->bits = 64;
	ret->machine = strdup ("AMD64");
	ret->rclass = strdup ("dmp64");
	ret->type = strdup ("Windows Crash Dump");
	ret->has_va = true;

	switch (obj->header->ProductType) {
	case MDMP_VER_NT_WORKSTATION:
		ret->os = r_str_newf ("Windows NT Workstation %d.%d",
		obj->header->MajorVersion,
		obj->header->MinorVersion);
		break;
	case MDMP_VER_NT_DOMAIN_CONTROLLER:
		ret->os = r_str_newf ("Windows NT Server Domain Controller %d.%d",
		obj->header->MajorVersion,
		obj->header->MinorVersion);
		break;
	case MDMP_VER_NT_SERVER:
		ret->os = r_str_newf ("Windows NT Server %d.%d",
		obj->header->MajorVersion,
		obj->header->MinorVersion);
		break;
	default:
		ret->os = strdup ("Unknown");
		break;
	}

	return ret;
}

static RList *sections(RBinFile *bf) {
	dmp_page_desc *page;
	RListIter *it;
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->bo->bin_obj;

	RList *ret = r_list_newf (free);
	r_list_foreach (obj->pages, it, page) {
		RBinSection *ptr = R_NEW0 (RBinSection);
		if (R_LIKELY (ptr)) {
			ptr->name = strdup ("Memory_Section");
			ptr->paddr = page->file_offset;
			ptr->size = DMP_PAGE_SIZE;
			ptr->vaddr = page->start;
			ptr->vsize = DMP_PAGE_SIZE;
			ptr->add = true;
			ptr->perm = R_PERM_R;
			r_list_append (ret, ptr);
		}
	}
	return ret;
}

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (buf, false);
	struct r_bin_dmp64_obj_t *res = r_bin_dmp64_new_buf (buf);
	if (res) {
		sdb_ns_set (bf->sdb, "info", res->kv);
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[8];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) == 8) {
		return !memcmp (magic, DMP64_MAGIC, 8);
	}
	return false;
}

RBinPlugin r_bin_plugin_dmp64 = {
	.meta = {
		.name = "dmp64",
		.author = "abcSup",
		.desc = "Windows Crash Dump for x86-64",
		.license = "LGPL-3.0-only",
	},
	.destroy = &destroy,
	.get_sdb = &get_sdb,
	.header = &header,
	.info = &info,
	.load = &load,
	.check = &check,
	.sections = &sections
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dmp64,
	.version = R2_VERSION
};
#endif
