/* radare - LGPL - Copyright 2014-2022 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

// Taken from https://pebbledev.org/wiki/Applications
// Resource packs: https://github.com/google/pebble/blob/main/tools/pbpack.py

#define APP_NAME_BYTES 32
#define COMPANY_NAME_BYTES 32
#define RESOURCE_PACK_MANIFEST_SIZE 12
#define RESOURCE_PACK_ENTRY_SIZE 16
#define APP_RESOURCE_TABLE_SIZE 256
#define SYSTEM_RESOURCE_TABLE_SIZE 512

R_PACKED (
typedef struct  {
	ut8 major; //!< "compatibility" version number
	ut8 minor;
}) Version;

R_PACKED (
typedef struct  {
	char header[8];               //!< Sentinel value, should always be 'PBLAPP\0\0'
	Version struct_version;       //!< version of this structure's format
	Version sdk_version;          //!< version of the SDK used to build this app
	Version app_version;          //!< version of the app
	ut16 size;                    //!< size of the app binary, including this metadata but not the reloc table
	ut32 offset;                  //!< The entry point of this executable
	ut32 crc;                     //!< CRC of the app data only, ie, not including this struct or the reloc table at the end
	char name[APP_NAME_BYTES];        //!< Name to display on the menu
	char company[COMPANY_NAME_BYTES]; //!< Name of the maker of this app
	ut32 icon_resource_id;        //!< Resource ID within this app's bank to use as a 32x32 icon
	ut32 sym_table_addr;          //!< The system will poke the sdk's symbol table address into this field on load
	ut32 flags;                   //!< Bitwise OR of PebbleAppFlags
	ut32 reloc_list_start;        //!< The offset of the address relocation list
	ut32 num_reloc_entries;       //!< The number of entries in the address relocation list
	ut8 uuid[16];
}) PebbleAppInfo;

typedef struct {
	ut32 id;
	ut32 offset;
	ut32 size;
	ut32 crc;
} PebbleResourceEntry;

typedef struct {
	ut32 num_files;
	ut32 crc;
	ut32 timestamp;
	ut32 table_size;
	ut64 content_start;
} PebbleResourcePack;

static bool read_pebble_app_info(RBuffer *b, PebbleAppInfo *pai) {
	ut8 buf[sizeof (*pai)];
	if (r_buf_read_at (b, 0, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	const ut8 *p = buf;
	memcpy (pai->header, p, sizeof (pai->header));
	p += sizeof (pai->header);
	pai->struct_version.major = *p++;
	pai->struct_version.minor = *p++;
	pai->sdk_version.major = *p++;
	pai->sdk_version.minor = *p++;
	pai->app_version.major = *p++;
	pai->app_version.minor = *p++;
	pai->size = r_read_le16 (p);
	p += sizeof (ut16);
	pai->offset = r_read_le32 (p);
	p += sizeof (ut32);
	pai->crc = r_read_le32 (p);
	p += sizeof (ut32);
	memcpy (pai->name, p, sizeof (pai->name));
	p += sizeof (pai->name);
	memcpy (pai->company, p, sizeof (pai->company));
	p += sizeof (pai->company);
	pai->icon_resource_id = r_read_le32 (p);
	p += sizeof (ut32);
	pai->sym_table_addr = r_read_le32 (p);
	p += sizeof (ut32);
	pai->flags = r_read_le32 (p);
	p += sizeof (ut32);
	pai->reloc_list_start = r_read_le32 (p);
	p += sizeof (ut32);
	pai->num_reloc_entries = r_read_le32 (p);
	p += sizeof (ut32);
	memcpy (pai->uuid, p, sizeof (pai->uuid));
	return !memcmp (pai->header, "PBLAPP\x00\x00", 8);
}

static bool read_resource_entry(RBuffer *b, ut64 at, PebbleResourceEntry *entry) {
	ut8 buf[RESOURCE_PACK_ENTRY_SIZE];
	if (r_buf_read_at (b, at, buf, sizeof (buf)) != sizeof (buf)) {
		return false;
	}
	entry->id = r_read_le32 (buf);
	entry->offset = r_read_le32 (buf + 4);
	entry->size = r_read_le32 (buf + 8);
	entry->crc = r_read_le32 (buf + 12);
	return true;
}

static bool read_resource_pack_with_table(RBuffer *b, ut32 table_size, PebbleResourcePack *pack) {
	ut64 size = r_buf_size (b);
	ut64 content_start = RESOURCE_PACK_MANIFEST_SIZE + (ut64)table_size * RESOURCE_PACK_ENTRY_SIZE;
	if (size < content_start) {
		return false;
	}
	ut8 manifest[RESOURCE_PACK_MANIFEST_SIZE];
	if (r_buf_read_at (b, 0, manifest, sizeof (manifest)) != sizeof (manifest)) {
		return false;
	}
	ut32 num_files = r_read_le32 (manifest);
	if (num_files > table_size) {
		return false;
	}
	ut64 content_size = size - content_start;
	ut64 max_end = 0;
	ut32 i;
	// Keep damaged packs inspectable: bounds, not payload CRCs, define extractability.
	for (i = 0; i < num_files; i++) {
		PebbleResourceEntry entry;
		ut64 at = RESOURCE_PACK_MANIFEST_SIZE + (ut64)i * RESOURCE_PACK_ENTRY_SIZE;
		if (!read_resource_entry (b, at, &entry) || entry.id != i + 1) {
			return false;
		}
		ut64 end = (ut64)entry.offset + entry.size;
		if (end > content_size) {
			return false;
		}
		max_end = R_MAX (max_end, end);
	}
	ut8 padding[RESOURCE_PACK_ENTRY_SIZE];
	for (; i < table_size; i++) {
		ut64 at = RESOURCE_PACK_MANIFEST_SIZE + (ut64)i * RESOURCE_PACK_ENTRY_SIZE;
		if (r_buf_read_at (b, at, padding, sizeof (padding)) != sizeof (padding)
			|| !r_mem_is_zero (padding, sizeof (padding))) {
			return false;
		}
	}
	if (max_end != content_size) {
		return false;
	}
	pack->num_files = num_files;
	pack->crc = r_read_le32 (manifest + 4);
	pack->timestamp = r_read_le32 (manifest + 8);
	pack->table_size = table_size;
	pack->content_start = content_start;
	return true;
}

static bool read_resource_pack(RBuffer *b, PebbleResourcePack *pack) {
	return read_resource_pack_with_table (b, APP_RESOURCE_TABLE_SIZE, pack)
		|| read_resource_pack_with_table (b, SYSTEM_RESOURCE_TABLE_SIZE, pack);
}

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[8];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) == sizeof (magic)
		&& !memcmp (magic, "PBLAPP\x00\x00", 8)) {
		return true;
	}
	PebbleResourcePack pack;
	return read_resource_pack (b, &pack);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

static RBinInfo* info(RBinFile *bf) {
	PebbleResourcePack pack;
	if (read_resource_pack (bf->buf, &pack)) {
		RBinInfo *ret = R_NEW0 (RBinInfo);
		ret->file = strdup (bf->file);
		ret->type = strdup ("Pebble resource pack");
		ret->bclass = strdup (pack.table_size == APP_RESOURCE_TABLE_SIZE? "application": "system");
		ret->rclass = strdup ("resource pack");
		ret->os = strdup ("pebble");
		ret->subsystem = strdup ("pebble");
		ret->machine = strdup ("watch");
		ret->has_va = false;
		ret->bits = 8;
		return ret;
	}
	PebbleAppInfo pai = {0};
	if (!read_pebble_app_info (bf->buf, &pai)) {
		R_LOG_ERROR ("Truncated Header");
		return NULL;
	}
	RBinInfo *ret = R_NEW0 (RBinInfo);
	ret->file = strdup (bf->file);
	ret->type = strdup ("pebble");
	ret->bclass = r_str_ndup (pai.name, 32);
	r_str_sanitize (ret->bclass);
	ret->rclass = r_str_ndup (pai.company, 32);
	ret->os = strdup ("pebble");
	ret->subsystem = strdup ("pebble");
	ret->machine = strdup ("watch");
	ret->arch = strdup ("arm"); // thumb only
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static bool sections_vec(RBinFile *bf) {
	PebbleResourcePack pack;
	if (read_resource_pack (bf->buf, &pack)) {
		RVecRBinSection_clear (&bf->bo->sections_vec);
		RBinSection *ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		ptr->name = strdup ("manifest");
		ptr->vaddr = ptr->paddr = 0;
		ptr->vsize = ptr->size = RESOURCE_PACK_MANIFEST_SIZE;
		ptr->perm = R_PERM_R;
		ptr->add = true;

		ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		ptr->name = strdup ("resource_table");
		ptr->vaddr = ptr->paddr = RESOURCE_PACK_MANIFEST_SIZE;
		ptr->vsize = ptr->size = (ut64)pack.table_size * RESOURCE_PACK_ENTRY_SIZE;
		ptr->perm = R_PERM_R;
		ptr->add = true;

		ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		ptr->name = strdup ("resources");
		ptr->vaddr = ptr->paddr = pack.content_start;
		ptr->vsize = ptr->size = r_buf_size (bf->buf) - pack.content_start;
		ptr->perm = R_PERM_R;
		ptr->add = true;
		return true;
	}
	ut64 textsize = UT64_MAX;
	RBinSection *ptr = NULL;
	PebbleAppInfo pai = {{0}};
	if (!read_pebble_app_info (bf->buf, &pai)) {
		R_LOG_ERROR ("Truncated Header");
		return false;
	}
	RVecRBinSection_clear (&bf->bo->sections_vec);
	// TODO: load all relocs
	ut64 sz = pai.num_reloc_entries * sizeof (ut32);
	ut64 ss = pai.reloc_list_start;
	if (ss < r_buf_size (bf->buf)) {
		ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
		ptr->name = strdup ("relocs");
		if (ss + sz >= r_buf_size (bf->buf)) {
			ut64 left = r_buf_size (bf->buf) - ss;
			sz = left;
		}
		ptr->vaddr = ptr->paddr = ss;
		ptr->vsize = ptr->size = sz;
		ptr->perm = R_PERM_RWX;
		ptr->add = true;
		const ut64 vaddr = ptr->vaddr;
		if (vaddr < textsize) {
			textsize = vaddr;
		}
	}

	// imho this must be a symbol
	ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	ptr->name = strdup ("symtab");
	ptr->vsize = ptr->size = 0;
	ptr->vaddr = ptr->paddr = pai.sym_table_addr;
	ptr->perm = R_PERM_R;
	ptr->add = true;
	const ut64 symtab_vaddr = ptr->vaddr;
	if (symtab_vaddr < textsize) {
		textsize = symtab_vaddr;
	}

	ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	ptr->name = strdup ("text");
	ptr->vaddr = ptr->paddr = 0x80;
	ptr->vsize = ptr->size = textsize - ptr->paddr;
	ptr->perm = R_PERM_RWX;
	ptr->add = true;

	ptr = RVecRBinSection_emplace_back (&bf->bo->sections_vec);
	ptr->name = strdup ("header");
	ptr->vsize = ptr->size = sizeof (PebbleAppInfo);
	ptr->vaddr = ptr->paddr = 0;
	ptr->perm = R_PERM_R;
	ptr->add = true;

	return true;
}

#if 0
static RList* relocs(RBinFile *bf) {
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	ut64 got_addr;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	return ret;
}
#endif

static RList* entries(RBinFile *bf) {
	PebbleResourcePack pack;
	if (read_resource_pack (bf->buf, &pack)) {
		return r_list_newf (free);
	}
	PebbleAppInfo pai = {{0}};
	if (!read_pebble_app_info (bf->buf, &pai)) {
		R_LOG_ERROR ("Truncated Header");
		return NULL;
	}
	RList *ret = r_list_new ();
	ret->free = free;
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	ptr->paddr = pai.offset;
	ptr->vaddr = pai.offset;
	r_list_append (ret, ptr);
	return ret;
}

static bool load_resources(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && bf->buf, false);
	PebbleResourcePack pack;
	if (!read_resource_pack (bf->buf, &pack)) {
		return true;
	}
	ut32 i;
	for (i = 0; i < pack.num_files; i++) {
		PebbleResourceEntry entry;
		ut64 at = RESOURCE_PACK_MANIFEST_SIZE + (ut64)i * RESOURCE_PACK_ENTRY_SIZE;
		if (!read_resource_entry (bf->buf, at, &entry)) {
			return false;
		}
		RBinResource *resource = RVecRBinResource_emplace_back (&bf->bo->resources_vec);
		if (!resource) {
			return false;
		}
		resource->name = r_str_newf ("%u", entry.id);
		resource->type = strdup ("RESOURCE");
		if (!resource->name || !resource->type) {
			return false;
		}
		resource->paddr = pack.content_start + entry.offset;
		resource->vaddr = resource->paddr;
		resource->size = entry.size;
		resource->id = entry.id;
		resource->index = i;
		resource->type_id = UT32_MAX;
	}
	return true;
}

RBinPlugin r_bin_plugin_pebble = {
	.meta = {
		.name = "pebble",
		.desc = "Pebble Watch App and Resource Pack",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = entries,
	.sections_vec = &sections_vec,
	.info = &info,
	.load_resources = &load_resources,
	//.relocs = &relocs
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pebble,
	.version = R2_VERSION
};
#endif
