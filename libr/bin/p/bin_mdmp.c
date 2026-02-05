/* radare2 - LGPL - Copyright 2016-2025 - Davis, Alex Kornitzer */

#include <r_util/r_print.h>
#include <r_bin.h>
#include <r_endian.h>
#include "mdmp/mdmp.h"

static Sdb *get_sdb(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	RBinMdmpObj *mdmp = (RBinMdmpObj*)bf->bo->bin_obj;
	return (mdmp && mdmp->kv) ? mdmp->kv: NULL;
}

static void destroy(RBinFile *bf) {
	r_bin_mdmp_free ((RBinMdmpObj *)bf->bo->bin_obj);
}

static RList* entries(RBinFile *bf) {
	RBinMdmpObj *mdmp = (RBinMdmpObj*)bf->bo->bin_obj;
	RListIter *it;

	RList *ret = r_list_newf (free);
	if (R_LIKELY (ret)) {
		struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
		r_list_foreach (mdmp->pe32_bins, it, pe32_bin) {
			RList *list = Pe32_r_bin_mdmp_pe_get_entrypoint (pe32_bin);
			r_list_join (ret, list);
			r_list_free (list);
		}
		struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
		r_list_foreach (mdmp->pe64_bins, it, pe64_bin) {
			RList *list = Pe64_r_bin_mdmp_pe_get_entrypoint (pe64_bin);
			r_list_join (ret, list);
			r_list_free (list);
		}
	}

	return ret;
}

/* Extract RTM revision from system modules (ntoskrnl.exe or ntdll.dll).
 * Returns revision number if found and validated, 0 otherwise. */
static ut32 extract_rtm_from_modules(RBinMdmpObj *mdmp, ut32 major, ut32 minor, ut32 build) {
	R_RETURN_VAL_IF_FAIL (mdmp && mdmp->streams.modules, 0);

	struct minidump_module *module;
	RListIter *it;
	ut8 b[512];
	char module_name[1024];
	ut32 revision = 0;
	ut32 mod_major, mod_minor, mod_build;
	ut32 str_length;
	int t;

	/* Try ntoskrnl.exe first (kernel), then ntdll.dll */
	static const char * const target_modules[] = { "ntoskrnl.exe", "ntdll.dll", NULL };

	for (t = 0; target_modules[t]; t++) {
		r_list_foreach (mdmp->streams.modules, it, module) {
			if (module->module_name_rva + sizeof (struct minidump_string) >= r_buf_size (mdmp->b)) {
				continue;
			}
			if (r_buf_read_at (mdmp->b, module->module_name_rva, (ut8 *)&b, sizeof (b)) < sizeof (struct minidump_string)) {
				continue;
			}
			/* Read length field using endian-safe API */
			str_length = r_read_le32 (b);
			/* Validate string length (max reasonable length for a module name) */
			if (str_length == 0 || str_length > 256) {
				continue;
			}
			/* Validate bounds: length is in UTF-16 characters, need to multiply by 2 for bytes */
			if (module->module_name_rva + sizeof (struct minidump_string) + (str_length * 2) > r_buf_size (mdmp->b)) {
				continue;
			}
			memset (module_name, 0, sizeof (module_name));
			r_str_utf16_to_utf8 ((ut8 *)module_name, str_length * 4,
				(const ut8 *)(b + sizeof (ut32)), str_length, mdmp->endian);

			/* Extract just the filename from the full path */
			const char *filename = strrchr (module_name, '\\');
			if (!filename) {
				filename = strrchr (module_name, '/');
			}
			if (filename) {
				filename++;
			} else {
				filename = module_name;
			}

			/* Case-insensitive comparison */
			if (!r_str_casecmp (filename, target_modules[t])) {
				/* Validate version_info signature before extracting version */
				if (module->version_info.dw_signature != 0xFEEF04BD) {
					continue;
				}
				/* Extract version from vs_fixedfileinfo */
				mod_major = (module->version_info.dw_file_version_ms >> 16) & 0xFFFF;
				mod_minor = module->version_info.dw_file_version_ms & 0xFFFF;
				mod_build = (module->version_info.dw_file_version_ls >> 16) & 0xFFFF;
				revision = module->version_info.dw_file_version_ls & 0xFFFF;

				/* For ntdll.dll (user-mode dumps), use revision if valid
				 * For ntoskrnl.exe (kernel-mode), require exact version match */
				if (t == 1 && revision > 0) {
					/* ntdll.dll found - use its revision */
					return revision;
				} else if (t == 0 && mod_major == major && mod_minor == minor && mod_build == build && revision > 0) {
					/* ntoskrnl.exe with matching version */
					return revision;
				}
			}
		}
	}

	return 0;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	RBinMdmpObj *mdmp = bf->bo->bin_obj;
	if (!mdmp) {
		return NULL;
	}
	ret->big_endian = mdmp->endian;
	ret->claimed_checksum = r_str_newf ("0x%08x", mdmp->hdr->check_sum);  // FIXME: Leaks
	ret->file = bf->file ? strdup (bf->file) : NULL;
	ret->has_va = true;
	ret->rclass = strdup ("mdmp");
	ret->rpath = strdup ("NONE");
	ret->type = strdup ("MDMP (MiniDump crash report data)");

	// FIXME: Needed to fix issue with PLT resolving. Can we get away with setting this for all children bins?
	ret->has_lit = true;

	r_strf_var (k, 32, "0x%08"PFMT64x, mdmp->hdr->flags);
	sdb_set (bf->sdb, "mdmp.flags", k, 0);
	sdb_num_set (bf->sdb, "mdmp.streams", mdmp->hdr->number_of_streams, 0);

	if (mdmp->streams.system_info) {
		switch (mdmp->streams.system_info->processor_architecture) {
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

		ut32 major = mdmp->streams.system_info->major_version;
		ut32 minor = mdmp->streams.system_info->minor_version;
		ut32 build = mdmp->streams.system_info->build_number;
		ut32 revision = extract_rtm_from_modules (mdmp, major, minor, build);
		char *version_str = NULL;
		const char *product_type_str = "Unknown";

		ret->os = strdup ("windows");

		/* Store detailed version information in SDB for iV command */
		switch (mdmp->streams.system_info->product_type) {
		case MDMP_VER_NT_WORKSTATION:
			product_type_str = "Workstation";
			break;
		case MDMP_VER_NT_DOMAIN_CONTROLLER:
			product_type_str = "Server Domain Controller";
			break;
		case MDMP_VER_NT_SERVER:
			product_type_str = "Server";
			break;
		}
		if (revision > 0) {
			version_str = r_str_newf ("Windows NT %s %d.%d.%d.%d",
				product_type_str, major, minor, build, revision);
		} else {
			version_str = r_str_newf ("Windows NT %s %d.%d.%d",
				product_type_str, major, minor, build);
		}
		sdb_set (bf->sdb, "mdmp.os_version", version_str, 0);
		sdb_num_set (bf->sdb, "mdmp.os_major", major, 0);
		sdb_num_set (bf->sdb, "mdmp.os_minor", minor, 0);
		sdb_num_set (bf->sdb, "mdmp.os_build", build, 0);
		if (revision > 0) {
			sdb_num_set (bf->sdb, "mdmp.os_revision", revision, 0);
		}
		sdb_set (bf->sdb, "mdmp.os_product_type", product_type_str, 0);
		R_FREE (version_str);
	}

	return ret;
}

static RList* libs(RBinFile *bf) {
	char *ptr = NULL;
	int i;
	struct r_bin_pe_lib_t *libs = NULL;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret = NULL;
	RListIter *it;

	if (!bf || !bf->bo || !bf->bo->bin_obj) {
		return NULL;
	}
	if (!(ret = r_list_newf (free))) {
		return NULL;
	}

	RBinMdmpObj *mdmp = (RBinMdmpObj*)bf->bo->bin_obj;

	/* TODO: Resolve module name for lib, or filter to remove duplicates,
	** rather than the vaddr :) */
	r_list_foreach (mdmp->pe32_bins, it, pe32_bin) {
		if (!(libs = Pe32_r_bin_pe_get_libs (pe32_bin->bin))) {
			return ret;
		}
		for (i = 0; !libs[i].last; i++) {
			ptr = r_str_newf ("[0x%.08" PFMT64x "] - %s", pe32_bin->vaddr, libs[i].name);
			r_list_append (ret, ptr);
		}
		free (libs);
	}
	r_list_foreach (mdmp->pe64_bins, it, pe64_bin) {
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

static bool load(RBinFile *bf, RBuffer *buf, ut64 loadaddr) {
	R_RETURN_VAL_IF_FAIL (buf, false);
	struct r_bin_mdmp_obj *res = r_bin_mdmp_new_buf (buf);
	if (R_LIKELY (res)) {
		sdb_ns_set (bf->sdb, "info", res->kv);
		bf->bo->bin_obj = res;
		return true;
	}
	return false;
}

static RList *sections(RBinFile *bf) {
	struct minidump_memory_descriptor *memory;
	struct minidump_memory_descriptor64 *memory64;
	struct minidump_module *module;
	struct minidump_string *str;
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *pe_secs;
	RListIter *it, *it0;
	RBinSection *ptr;
	ut64 index;

	struct r_bin_mdmp_obj *obj = (struct r_bin_mdmp_obj *)bf->bo->bin_obj;

	RList *ret = r_list_newf (free);

	/* TODO: Can't remove the memories from this section until get_vaddr is
	** implemented correctly, currently it is never called!?!? Is it a
	** relic? */
	r_list_foreach (obj->streams.memories, it, memory) {
		ptr = R_NEW0 (RBinSection);
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
		ptr = R_NEW0 (RBinSection);
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

		ptr = R_NEW0 (RBinSection);
		if (module->module_name_rva + sizeof (struct minidump_string) >= r_buf_size (obj->b)) {
			R_FREE (ptr);
			continue;
		}
		r_buf_read_at (obj->b, module->module_name_rva, (ut8*)&b, sizeof (b));
		ut32 str_length = r_read_le32 (b);
		int ptr_name_len = (str_length + 2) * 4;
		if (ptr_name_len < 1 || ptr_name_len > sizeof (b) - 4) {
			R_FREE (ptr);
			continue;
		}
		if (module->module_name_rva + str_length > r_buf_size (obj->b)) {
			R_FREE (ptr);
			break;
		}
		ptr->name = calloc (1, ptr_name_len);
		if (!ptr->name) {
			R_FREE (ptr);
			continue;
		}
		r_str_utf16_to_utf8 ((ut8 *)ptr->name, str_length * 4,
				(const ut8 *)(b + sizeof (ut32)), str_length, obj->endian);
		ptr->vaddr = module->base_of_image;
		ptr->vsize = module->size_of_image;
		ptr->paddr = r_bin_mdmp_get_paddr (obj, ptr->vaddr);
		ptr->size = module->size_of_image;
		ptr->add = false;
		ptr->has_strings = false;
		/* As this is an encompassing section we will set the RWX to 0 */
		ptr->perm = 0;

		if (!r_list_append (ret, ptr)) {
			R_FREE (ptr);
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
	R_LOG_INFO ("Parsing data sections for large dumps can take time");
	R_LOG_INFO ("Please be patient (but if strings ain't your thing try with -z)");
	return ret;
}

static RList *mem(RBinFile *bf) {
	struct minidump_location_descriptor *location = NULL;
	struct minidump_memory_descriptor *module;
	struct minidump_memory_descriptor64 *module64;
	struct minidump_memory_info *mem_info;
	RListIter *it;
	RBinMem *ptr;
	ut64 index;
	ut64 state, type, a_protect;

	RList *ret = r_list_newf (r_bin_mem_free);
	if (!ret) {
		return NULL;
	}

	struct r_bin_mdmp_obj *obj = (struct r_bin_mdmp_obj *)R_UNWRAP3 (bf, bo, bin_obj);
	if (!obj) {
		return ret;
	}

	/* [1] As there isnt a better place to put this info at the moment we will
	** mash it into the name field, but without enumeration for now  */
	r_list_foreach (obj->streams.memories, it, module) {
		ptr = R_NEW0 (RBinMem);
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
		ptr->name = r_str_newf ("paddr=0x%08"PFMT32x" state=0x%08"PFMT64x
					" type=0x%08"PFMT64x" allocation_protect=0x%08"PFMT64x" Memory_Section",
					location->rva, state, type, a_protect);

		r_list_append (ret, ptr);
	}

	index = obj->streams.memories64.base_rva;
	r_list_foreach (obj->streams.memories64.memories, it, module64) {
		ptr = R_NEW0 (RBinMem);
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
		ptr->name = r_str_newf ("paddr=0x%08"PFMT64x" state=0x%08"PFMT64x
					" type=0x%08"PFMT64x" allocation_protect=0x%08"PFMT64x" Memory_Section",
					index, state, type, a_protect);

		index += module64->data_size;

		r_list_append (ret, ptr);
	}

	return ret;
}

static RList* relocs(RBinFile *bf) {
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RListIter *it;
	RList* ret = r_list_newf (free);
	if (!ret) {
		return NULL;
	}
	RBinMdmpObj *mdmp = (RBinMdmpObj*)bf->bo->bin_obj;
	r_list_foreach (mdmp->pe32_bins, it, pe32_bin) {
		if (pe32_bin->bin && pe32_bin->bin->relocs) {
			r_list_join (ret, pe32_bin->bin->relocs);
		}
	}
	r_list_foreach (mdmp->pe64_bins, it, pe64_bin) {
		if (pe64_bin->bin && pe64_bin->bin->relocs) {
			r_list_join (ret, pe64_bin->bin->relocs);
		}
	}
	return ret;
}

static RList* imports(RBinFile *bf) {
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret = NULL, *list;
	RListIter *it;

	if (!(ret = r_list_newf ((RListFree)r_bin_import_free))) {
		return NULL;
	}
	RBinMdmpObj *mdmp = (RBinMdmpObj*)bf->bo->bin_obj;
	r_list_foreach (mdmp->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_imports (pe32_bin);
		if (list) {
			r_list_join (ret, list);
			r_list_free (list);
		}
	}
	r_list_foreach (mdmp->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_imports (pe64_bin);
		if (list) {
			r_list_join (ret, list);
			r_list_free (list);
		}
	}
	return ret;
}

static RList* symbols(RBinFile *bf) {
	struct Pe32_r_bin_mdmp_pe_bin *pe32_bin;
	struct Pe64_r_bin_mdmp_pe_bin *pe64_bin;
	RList *ret, *list;
	RListIter *it;

	if (!(ret = r_list_newf ((RListFree)r_bin_import_free))) {
		return NULL;
	}

	RBinMdmpObj *mdmp = (RBinMdmpObj*)bf->bo->bin_obj;

	r_list_foreach (mdmp->pe32_bins, it, pe32_bin) {
		list = Pe32_r_bin_mdmp_pe_get_symbols (bf->rbin, pe32_bin);
		r_list_join (ret, list);
		r_list_free (list);
	}
	r_list_foreach (mdmp->pe64_bins, it, pe64_bin) {
		list = Pe64_r_bin_mdmp_pe_get_symbols (bf->rbin, pe64_bin);
		r_list_join (ret, list);
		r_list_free (list);
	}
	return ret;
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[6];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) == 6) {
		return !memcmp (magic, MDMP_MAGIC, 6);
	}
	return false;
}

RBinPlugin r_bin_plugin_mdmp = {
	.meta = {
		.name = "mdmp",
		.author = "Davis,Alex Kornitzer",
		.desc = "Windows minidump crash snapshot",
		.license = "LGPL-3.0-only",
	},
	.destroy = &destroy,
	.entries = entries,
	.get_sdb = &get_sdb,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.load = &load,
	.check = &check,
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