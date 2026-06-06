/* radare - LGPL - Copyright 2014-2022 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

// Taken from https://pebbledev.org/wiki/Applications

#define APP_NAME_BYTES 32
#define COMPANY_NAME_BYTES 32

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

static bool check(RBinFile *bf, RBuffer *b) {
	ut8 magic[8];
	if (r_buf_read_at (b, 0, magic, sizeof (magic)) != sizeof (magic)) {
		return false;
	}
	return !memcmp (magic, "PBLAPP\x00\x00", 8);
}

static bool load(RBinFile *bf, RBuffer *b, ut64 loadaddr) {
	return check (bf, b);
}

static ut64 baddr(RBinFile *bf) {
	return 0LL;
}

static RBinInfo* info(RBinFile *bf) {
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
	ret->os = strdup ("rtos");
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

RBinPlugin r_bin_plugin_pebble = {
	.meta = {
		.name = "pebble",
		.desc = "Pebble Watch App",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.load = &load,
	.check = &check,
	.baddr = &baddr,
	.entries = entries,
	.sections_vec = &sections_vec,
	.info = &info,
	//.relocs = &relocs
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pebble,
	.version = R2_VERSION
};
#endif
