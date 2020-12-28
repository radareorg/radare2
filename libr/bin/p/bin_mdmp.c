/* radare2 - LGPL - Copyright 2016-2018 - Davis, Alex Kornitzer */

#include <r_types.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <r_lib.h>
#include <r_bin.h>

#include "mdmp/mdmp.h"

static Sdb *get_sdb(RBinFile *bf) {
	r_return_val_if_fail (bf && bf->o, NULL);
	struct r_bin_mdmp_obj *obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;
	return (obj && obj->kv) ? obj->kv: NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_mdmp_free ((struct r_bin_mdmp_obj*)bf->o->bin_obj);
}

static RList* entries(RBinFile *bf) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RListIter *it;
	RList* ret, *list;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_entrypoint (pe32_bin);
		r_list_join (ret, list);
		r_list_free (list);
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_entrypoint (pe64_bin);
		r_list_join (ret, list);
		r_list_free (list);
	}

	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	struct r_bin_mdmp_obj *obj;
	RBinInfo *ret;

	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	ret->big_endian = obj->endian;
	ret->claimed_checksum = strdup (sdb_fmt ("0x%08x", obj->hdr->check_sum));  // FIXME: Leaks
	ret->file = bf->file ? strdup (bf->file) : NULL;
	ret->has_va = true;
	ret->rclass = strdup ("mdmp");
	ret->rpath = strdup ("NONE");
	ret->type = strdup ("MDMP (MiniDump crash report data)");

	// FIXME: Needed to fix issue with PLT resolving. Can we get away with setting this for all children bins?
	ret->has_lit = true;

	sdb_set (bf->sdb, "mdmp.flags", sdb_fmt ("0x%08"PFMT64x, obj->hdr->flags), 0);
	sdb_num_set (bf->sdb, "mdmp.streams", obj->hdr->number_of_streams, 0);

	if (obj->streams.system_info) {
		switch (obj->streams.system_info->processor_architecture) {
		case MDMP_PROCESSOR_ARCHITECTURE_INTEL:
			ret->machine = strdup ("i386");
			ret->arch = strdup ("x86");
			ret->bits = 32;
			break;
		case MDMP_PROCESSOR_ARCHITECTURE_ARM:
			ret->machine = strdup ("ARM");
			ret->big_endian = false;
			break;
		case MDMP_PROCESSOR_ARCHITECTURE_IA64:
			ret->machine = strdup ("IA64");
			ret->arch = strdup ("IA64");
			ret->bits = 64;
			break;
		case MDMP_PROCESSOR_ARCHITECTURE_AMD64:
			ret->machine = strdup ("AMD64");
			ret->arch = strdup ("x86");
			ret->bits = 64;
			break;
		default:
			ret->machine = strdup ("Unknown");
			break;
		}

		switch (obj->streams.system_info->product_type) {
		case MDMP_VER_NT_WORKSTATION:
			ret->os = r_str_newf ("Windows NT Workstation %d.%d.%d",
			obj->streams.system_info->major_version,
			obj->streams.system_info->minor_version,
			obj->streams.system_info->build_number);
			break;
		case MDMP_VER_NT_DOMAIN_CONTROLLER:
			ret->os = r_str_newf ("Windows NT Server Domain Controller %d.%d.%d",
			obj->streams.system_info->major_version,
			obj->streams.system_info->minor_version,
			obj->streams.system_info->build_number);
			break;
		case MDMP_VER_NT_SERVER:
			ret->os = r_str_newf ("Windows NT Server %d.%d.%d",
			obj->streams.system_info->major_version,
			obj->streams.system_info->minor_version,
			obj->streams.system_info->build_number);
			break;
		default:
			ret->os = strdup ("Unknown");
		}
	}

	return ret;
}

static RList* libs(RBinFile *bf) {
	char *ptr = NULL;
	int i;
	struct r_bin_mdmp_obj *obj;
	struct r_bin_pe_lib_t *libs = NULL;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret = NULL;
	RListIter *it;

	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	/* TODO: Resolve module name for lib, or filter to remove duplicates,
	** rather than the vaddr :) */
	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		if (!(libs = Pe32_r_bin_pe_get_libs (pe32_bin->bin))) {
			return ret;
		}
		for (i = 0; !libs[i].last; i++) {
			ptr = r_str_newf ("[0x%.08" PFMT64x "] - %s", pe32_bin->vaddr, libs[i].name);
			r_list_append (ret, ptr);
		}
		free (libs);
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		if (!(libs = Pe64_r_bin_pe_get_libs (pe64_bin->bin))) {
			return ret;
		}
		for (i = 0; !libs[i].last; i++) {
			ptr = r_str_newf ("[0x%.08"PFMT64x"] - %s", pe64_bin->vaddr, libs[i].name);
			r_list_append (ret, ptr);
		}
		free (libs);
	}
	return ret;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	r_return_val_if_fail (buf, false);
	struct r_bin_mdmp_obj *res = r_bin_mdmp_new_buf (buf);
	if (res) {
		sdb_ns_set (sdb, "info", res->kv);
		*bin_obj = res;
		return true;
	}
	return false;
}

static RList *sections(RBinFile *bf) {
	struct minidump_memory_descriptor *memory;
	struct minidump_memory_descriptor64 *memory64;
	struct minidump_module *module;
	struct minidump_string *str;
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret, *pe_secs;
	RListIter *it, *it0;
	RBinSection *ptr;
	ut64 index;

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	/* TODO: Can't remove the memories from this section until get_vaddr is
	** implemented correctly, currently it is never called!?!? Is it a
	** relic? */
	r_list_foreach (obj->streams.memories, it, memory) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		ptr->name = strdup ("Memory_Section");
		ptr->paddr = (memory->memory).rva;
		ptr->size = (memory->memory).data_size;
		ptr->vaddr = memory->start_of_memory_range;
		ptr->vsize = (memory->memory).data_size;
		ptr->add = true;
		ptr->has_strings = false;

		ptr->perm = r_bin_mdmp_get_perm (obj, ptr->vaddr);

		r_list_append (ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, memory64) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}

		ptr->name = strdup ("Memory_Section");
		ptr->paddr = index;
		ptr->size = memory64->data_size;
		ptr->vaddr = memory64->start_of_memory_range;
		ptr->vsize = memory64->data_size;
		ptr->add = true;
		ptr->has_strings = false;

		ptr->perm = r_bin_mdmp_get_perm (obj, ptr->vaddr);

		r_list_append (ret, ptr);

		index += memory64->data_size;
	}

	// XXX: Never add here as they are covered above
	r_list_foreach (obj->streams.modules, it, module) {
		ut8 b[512];

		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		if (module->module_name_rva + sizeof (struct minidump_string) >= r_buf_size (obj->b)) {
			free (ptr);
			continue;
		}
		r_buf_read_at (obj->b, module->module_name_rva, (ut8*)&b, sizeof (b));
		str = (struct minidump_string *)b;
		int ptr_name_len = (str->length + 2) * 4;
		if (ptr_name_len < 1 || ptr_name_len > sizeof (b) - 4) {
			continue;
		}
		if (module->module_name_rva + str->length > r_buf_size (obj->b)) {
			free (ptr);
			break;
		}
		ptr->name = calloc (1, ptr_name_len);
		if (!ptr->name) {
			free (ptr);
			continue;
		}
		r_str_utf16_to_utf8 ((ut8 *)ptr->name, str->length * 4,
				(const ut8 *)(&str->buffer), str->length, obj->endian);
		ptr->vaddr = module->base_of_image;
		ptr->vsize = module->size_of_image;
		ptr->paddr = r_bin_mdmp_get_paddr (obj, ptr->vaddr);
		ptr->size = module->size_of_image;
		ptr->add = false;
		ptr->has_strings = false;
		/* As this is an encompassing section we will set the RWX to 0 */
		ptr->perm = 0;

		if (!r_list_append (ret, ptr)) {
			free (ptr);
			break;
		}

		/* Grab the pe sections */
		r_list_foreach (obj->pe32_bins, it0, pe32_bin) {
			if (pe32_bin->vaddr == module->base_of_image && pe32_bin->bin) {
				pe_secs = Pe32_r_bin_mdmp_pe_get_sections(pe32_bin);
				r_list_join (ret, pe_secs);
				r_list_free (pe_secs);
			}
		}
		r_list_foreach (obj->pe64_bins, it0, pe64_bin) {
			if (pe64_bin->vaddr == module->base_of_image && pe64_bin->bin) {
				pe_secs = Pe64_r_bin_mdmp_pe_get_sections(pe64_bin);
				r_list_join (ret, pe_secs);
				r_list_free (pe_secs);
			}
		}
	}
	eprintf ("[INFO] Parsing data sections for large dumps can take time, "
		"please be patient (but if strings ain't your thing try with "
		"-z)!\n");
	return ret;
}

static RList *mem(RBinFile *bf) {
	struct minidump_location_descriptor *location = NULL;
	struct minidump_memory_descriptor *module;
	struct minidump_memory_descriptor64 *module64;
	struct minidump_memory_info *mem_info;
	struct r_bin_mdmp_obj *obj;
	RList *ret;
	RListIter *it;
	RBinMem *ptr;
	ut64 index;
	ut64 state, type, a_protect;

	if (!(ret = r_list_newf (r_bin_mem_free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	/* [1] As there isnt a better place to put this info at the moment we will
	** mash it into the name field, but without enumeration for now  */
	r_list_foreach (obj->streams.memories, it, module) {
		if (!(ptr = R_NEW0 (RBinMem))) {
			return ret;
		}
		ptr->addr = module->start_of_memory_range;
		ptr->size = location? location->data_size: 0;
		ptr->perms = r_bin_mdmp_get_perm (obj, ptr->addr);

		/* [1] */
		state = type = a_protect = 0;
		if ((mem_info = r_bin_mdmp_get_mem_info (obj, ptr->addr))) {
			state = mem_info->state;
			type = mem_info->type;
			a_protect = mem_info->allocation_protect;
		}
		location = &(module->memory);
		ptr->name = strdup (sdb_fmt ("paddr=0x%08"PFMT32x" state=0x%08"PFMT64x
					" type=0x%08"PFMT64x" allocation_protect=0x%08"PFMT64x" Memory_Section",
					location->rva, state, type, a_protect));

		r_list_append (ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, module64) {
		if (!(ptr = R_NEW0 (RBinMem))) {
			return ret;
		}
		ptr->addr = module64->start_of_memory_range;
		ptr->size = module64->data_size;
		ptr->perms = r_bin_mdmp_get_perm (obj, ptr->addr);

		/* [1] */
		state = type = a_protect = 0;
		if ((mem_info = r_bin_mdmp_get_mem_info (obj, ptr->addr))) {
			state = mem_info->state;
			type = mem_info->type;
			a_protect = mem_info->allocation_protect;
		}
		ptr->name = strdup (sdb_fmt ("paddr=0x%08"PFMT64x" state=0x%08"PFMT64x
					" type=0x%08"PFMT64x" allocation_protect=0x%08"PFMT64x" Memory_Section",
					index, state, type, a_protect));

		index += module64->data_size;

		r_list_append (ret, ptr);
	}

	return ret;
}

static RList* relocs(RBinFile *bf) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RListIter *it;
	RList* ret;

	if (!(ret = r_list_new ())) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		if (pe32_bin->bin && pe32_bin->bin->relocs) {
			r_list_join (ret, pe32_bin->bin->relocs);
		}
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		if (pe64_bin->bin && pe64_bin->bin->relocs) {
			r_list_join (ret, pe64_bin->bin->relocs);
		}
	}

	return ret;
}

static RList* imports(RBinFile *bf) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret = NULL, *list;
	RListIter *it;

	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_imports (pe32_bin);
		if (list) {
			r_list_join (ret, list);
			r_list_free (list);
		}
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_imports (pe64_bin);
		if (list) {
			r_list_join (ret, list);
			r_list_free (list);
		}
	}
	return ret;
}

static RList* symbols(RBinFile *bf) {
	struct r_bin_mdmp_obj *obj;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret, *list;
	RListIter *it;

	if (!(ret = r_list_newf (r_bin_import_free))) {
		return NULL;
	}

	obj = (struct r_bin_mdmp_obj *)bf->o->bin_obj;

	r_list_foreach (obj->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_symbols (bf->rbin, pe32_bin);
		r_list_join (ret, list);
		r_list_free (list);
	}
	r_list_foreach (obj->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_symbols (bf->rbin, pe64_bin);
		r_list_join (ret, list);
		r_list_free (list);
	}
	return ret;
}

static bool check_buffer(RBuffer *b) {
	ut8 magic[6];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) == 6) {
		return !memcmp (magic, MDMP_MAGIC, 6);
	}
	return false;
}

RBinPlugin r_bin_plugin_mdmp = {
	.name = "mdmp",
	.desc = "Minidump format r_bin plugin",
	.license = "LGPL3",
	.destroy = &destroy,
	.entries = entries,
	.get_sdb = &get_sdb,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.mem = &mem,
	.relocs = &relocs,
	.sections = &sections,
	.symbols = &symbols,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdmp,
	.version = R2_VERSION
};
#endif
