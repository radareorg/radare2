#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "mdmp/mdmp.h"

static Sdb *get_sdb(RBinObject *o) {
	struct r_bin_mdmp_obj *bin;
	if (!o) return NULL;
	bin = (struct r_bin_mdmp_obj *) o->bin_obj;
	if (bin->kv) return bin->kv;
	return NULL;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	RBuffer *tbuf;
	void *res;
	if (!buf || sz == 0 || sz == UT64_MAX)
		return NULL;
	tbuf = r_buf_new_with_bytes (buf, sz);
	res = r_bin_mdmp_new_buf (tbuf);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes;
	ut64 sz;
	if (!arch || !arch->o || !arch->buf)
		return R_FALSE;
	bytes = r_buf_buffer (arch->buf);
	sz = r_buf_size (arch->buf);
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj != NULL;
}

static int destroy(RBinFile *arch) {
	r_bin_mdmp_free((struct r_bin_mdmp_obj *)arch->o->bin_obj);
	return true;
}

static int check_bytes(const ut8 *buf, ut64 size) {
	return (size > sizeof(MINIDUMP_HEADER) && ((PMINIDUMP_HEADER)buf)->Signature == MINIDUMP_SIGNATURE);
}

static int check(RBinFile *arch) {
	if (!arch || !arch->o || !arch->buf)
		return false;
	return check_bytes(r_buf_buffer(arch->buf), r_buf_size(arch->buf));
}

static RList *entries(RBinFile *arch) {
	RList *ret;
	if (!(ret = r_list_newf(free)))
		return NULL;
	return ret;
}

static RList *sections(RBinFile *arch) {
	RList *ret = NULL;
	RListIter *it;
	RBinSection *ptr = NULL;
	struct r_bin_mdmp_obj *obj = arch->o->bin_obj;
	PMINIDUMP_MODULE module;
	PMINIDUMP_STRING str;

	if (!(ret = r_list_newf(free)))
		return NULL;

	r_list_foreach (obj->modules, it, module) {
		if (!(ptr = R_NEW0(RBinSection))) {
			eprintf("Warning in mdmp sections: R_NEW0 failed\n");
			break;
		}
		if ((str = r_bin_mdmp_locate_string(obj, module->ModuleNameRva))) {
			//strncpy(ptr->name, (char *)str->Buffer, R_MIN(str->Length, R_BIN_SIZEOF_STRINGS));
		}
		ptr->size = module->SizeOfImage;
		ptr->vsize = module->SizeOfImage;
		ptr->paddr = (unsigned char *)module - obj->b->buf;
		//ptr->paddr = 0;//module->BaseOfImage;
		ptr->vaddr = module->BaseOfImage;
		ptr->srwx = 0;
		r_list_append(ret, ptr);
	}
	return ret;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0(RBinInfo);
	struct r_bin_mdmp_obj *obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	ret->file = strdup (arch->file);
	ret->rpath = strdup ("NONE");

	ret->big_endian = false;
	switch (obj->system_info->ProcessorArchitecture) {
	case WINDOWS_PROCESSOR_ARCHITECTURE_INTEL:
		ret->machine = strdup("i386");
		ret->arch = strdup("x86");
		ret->bits = 32;
		break;
	case WINDOWS_PROCESSOR_ARCHITECTURE_ARM:
		ret->machine = strdup ("ARM");
		ret->arch = strdup ("h8300");
		ret->bits = 16;
		ret->big_endian = false;
		break;
	case WINDOWS_PROCESSOR_ARCHITECTURE_IA64:
		ret->machine = strdup ("IA64");
		ret->arch = strdup ("IA64");
		ret->bits = 64;
		break;
	case WINDOWS_PROCESSOR_ARCHITECTURE_AMD64:
		ret->machine = strdup ("AMD 64");
		ret->arch = strdup ("x86");
		ret->bits = 64;
		break;
	default:
		strncpy(ret->machine, "unknown", R_BIN_SIZEOF_STRINGS);
	}
	switch (obj->system_info->ProductType) {
	case WINDOWS_VER_NT_WORKSTATION:
		ret->os = r_str_newf ("Windows NT Workstation %d.%d.%d",
			obj->system_info->MajorVersion,
			obj->system_info->MinorVersion,
			obj->system_info->BuildNumber);
		break;
	case WINDOWS_VER_NT_DOMAIN_CONTROLLER:
		ret->os = r_str_newf ("Windows NT Server Domain Controller %d.%d.%d",
			obj->system_info->MajorVersion,
			obj->system_info->MinorVersion,
			obj->system_info->BuildNumber);
		break;
	case WINDOWS_VER_NT_SERVER:
		ret->os = r_str_newf ("Windows NT Server %d.%d.%d",
			obj->system_info->MajorVersion,
			obj->system_info->MinorVersion,
			obj->system_info->BuildNumber);
		break;
	default:
		ret->os = strdup ("unknown");
	}
	return ret;
}

RBinPlugin r_bin_plugin_mdmp = {
	.name = "mdmp",
	.desc = "Minidump format r_bin plugin",
	.license = "UNLICENSE",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = &sections,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdmp
};
#endif
