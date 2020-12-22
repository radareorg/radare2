/* radare2 - LGPL - Copyright 2020 - abcSup */

#include <r_types.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <r_lib.h>
#include <r_bin.h>

#include "dmp/dmp64.h"

static Sdb *get_sdb(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o, NULL);
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->o->bin_obj;
	return (obj && obj->kv) ? obj->kv: NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_dmp64_free ((struct r_bin_dmp64_obj_t*)bf->o->bin_obj);
}

static void header(RBinFile *bf) {
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->o->bin_obj;
	struct r_bin_t *rbin = bf->rbin;
	rbin->cb_printf ("DUMP_HEADER64:\n");
	rbin->cb_printf ("  MajorVersion : 0x%08"PFMT32x"\n", obj->header->MajorVersion);
	rbin->cb_printf ("  MinorVersion : 0x%08"PFMT32x"\n", obj->header->MinorVersion);
	rbin->cb_printf ("  DirectoryTableBase : 0x%016"PFMT64x"\n", obj->header->DirectoryTableBase);
	rbin->cb_printf ("  PfnDataBase : 0x%016"PFMT64x"\n", obj->header->PfnDataBase);
	rbin->cb_printf ("  PsLoadedModuleList : 0x%016"PFMT64x"\n", obj->header->PsLoadedModuleList);
	rbin->cb_printf ("  PsActiveProcessHead : 0x%016"PFMT64x"\n", obj->header->PsActiveProcessHead);
	rbin->cb_printf ("  MachineImageType : 0x%08"PFMT32x"\n", obj->header->MachineImageType);
	rbin->cb_printf ("  NumberProcessors : 0x%08"PFMT32x"\n", obj->header->NumberProcessors);
	rbin->cb_printf ("  BugCheckCode : 0x%08"PFMT32x"\n", obj->header->BugCheckCode);
	rbin->cb_printf ("  BugCheckParameter1 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[0]);
	rbin->cb_printf ("  BugCheckParameter2 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[1]);
	rbin->cb_printf ("  BugCheckParameter3 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[2]);
	rbin->cb_printf ("  BugCheckParameter4 : 0x%016"PFMT64x"\n", obj->header->BugCheckCodeParameter[3]);
	rbin->cb_printf ("  KdDebuggerDataBlock : 0x%016"PFMT64x"\n", obj->header->KdDebuggerDataBlock);
	rbin->cb_printf ("  SecondaryDataState : 0x%08"PFMT32x"\n", obj->header->SecondaryDataState);
	rbin->cb_printf ("  ProductType : 0x%08"PFMT32x"\n", obj->header->ProductType);
	rbin->cb_printf ("  SuiteMask : 0x%08"PFMT32x"\n", obj->header->SuiteMask);

	if (obj->bmp_header) {
		rbin->cb_printf ("\nBITMAP_DUMP:\n");
		rbin->cb_printf ("  HeaderSize : 0x%08"PFMT64x"\n", obj->bmp_header->FirstPage);
		rbin->cb_printf ("  BitmapSize : 0x%08"PFMT64x"\n", obj->bmp_header->Pages);
		rbin->cb_printf ("  Pages : 0x%08"PFMT64x"\n", obj->bmp_header->TotalPresentPages);
	}
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->o->bin_obj;

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
	}

	return ret;
}

static RList *sections(RBinFile *bf) {
	dmp_page_desc *page;
	RList *ret;
	RListIter *it;
	RBinSection *ptr;
	struct r_bin_dmp64_obj_t *obj = (struct r_bin_dmp64_obj_t *)bf->o->bin_obj;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	r_list_foreach (obj->pages, it, page) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		ptr->name = strdup ("Memory_Section");
		ptr->paddr = page->file_offset;
		ptr->size = DMP_PAGE_SIZE;
		ptr->vaddr = page->start;
		ptr->vsize = DMP_PAGE_SIZE;
		ptr->add = true;
		ptr->perm = R_PERM_R;

		r_list_append (ret, ptr);
	}
	return ret;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (buf, false);
	struct r_bin_dmp64_obj_t *res = r_bin_dmp64_new_buf (buf);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
		*bin_obj = res;
		return true;
	}
	return false;
}

static bool check_buffer(RBuffer *b) {
	ut8 magic[8];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) == 8) {
		return !memcmp (magic, DMP64_MAGIC, 8);
	}
	return false;
}

RBinPlugin r_bin_plugin_dmp64 = {
	.name = "dmp64",
	.desc = "Windows Crash Dump x64 r_bin plugin",
	.license = "LGPL3",
	.destroy = &destroy,
	.get_sdb = &get_sdb,
	.header = &header,
	.info = &info,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.sections = &sections
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dmp64,
	.version = R2_VERSION
};
#endif
