/* radare - LGPL - 2014 - thatlemon@gmail.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/xbe/xbe.h"

static const char *kt_name[] = {
#include "../format/xbe/kernel.h"
};

static Sdb* get_sdb (RBinObject *o) {
	return NULL;
}

static int check_bytes(const ut8 *buf, ut64 size) {
	xbe_header *header = (xbe_header *)buf;
	return (size > sizeof(xbe_header) && header->magic == XBE_MAGIC);
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	const ut64 size = arch ? r_buf_size (arch->buf) : 0;

	if (!arch || !arch->o || !bytes)
		return R_FALSE;

	return check_bytes(bytes, size);
}

static int load(RBinFile *arch) {
	r_bin_xbe_obj_t *obj = NULL;
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	if (!arch || !arch->o)
		return R_FALSE;
	arch->o->bin_obj = malloc (sizeof (r_bin_plugin_xbe));
	if (!arch->o->bin_obj)
		return R_FALSE;
	obj = arch->o->bin_obj;

	if (obj) {
		obj->header = (xbe_header *)bytes;
		if ((obj->header->ep&0xf0000000) == 0x40000000) {
			// Sega Chihiro xbe
			obj->ep_key = XBE_EP_CHIHIRO;
			obj->kt_key = XBE_KP_CHIHIRO;
		} else if ((obj->header->ep ^ XBE_EP_RETAIL) > 0x1000000) {
			// Debug xbe
			obj->ep_key = XBE_EP_DEBUG;
			obj->kt_key = XBE_KP_DEBUG;
		} else {
			// Retail xbe
			obj->ep_key = XBE_EP_RETAIL;
			obj->kt_key = XBE_KP_RETAIL;
		}
		return R_TRUE;
	}

	return R_FALSE;
}

static int destroy(RBinFile *arch) {
	free(arch->o->bin_obj);
	r_buf_free (arch->buf);
	arch->buf = NULL;
	arch->o->bin_obj = NULL;
	return R_TRUE;
}

static RBinAddr* binsym(RBinFile *arch, int type) {
	RBinAddr *ret;
	r_bin_xbe_obj_t *obj;
	if (!arch || !arch->buf || type != R_BIN_SYM_MAIN)
		return NULL;
	obj = arch->o->bin_obj;
	ret = R_NEW0 (RBinAddr);
	if (!ret) return NULL;
	ret->vaddr = obj->header->ep ^ obj->ep_key;
	ret->paddr = ret->vaddr - obj->header->base;
	return ret;
}

static RList* entries(RBinFile *arch) {
	const r_bin_xbe_obj_t *obj;
	RList* ret;
	RBinAddr *ptr = R_NEW0 (RBinAddr);
	if (!arch || !arch->buf || !arch->o->bin_obj || !ptr)
		return NULL;
	ret = r_list_new ();
	if (!ret){
		free (ptr);
		return NULL;
	}
	ret->free = free;
	obj = arch->o->bin_obj;
	ptr->vaddr = obj->header->ep ^ obj->ep_key;
	ptr->paddr = ptr->vaddr - obj->header->base;
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *arch) {
	xbe_section *sect;
	r_bin_xbe_obj_t *obj;
	RList *ret;
	int i;

	if (!arch || !arch->o)
		return NULL;

	obj = arch->o->bin_obj;
	if (obj->header->sections < 1)
		return NULL;

	ret = r_list_new ();
	if (!ret)
		return NULL;

	if (!arch->buf) {
		free (ret);
		return NULL;
	}

	ret->free = free;

	sect = calloc (obj->header->sections, sizeof (xbe_section));
	if (!sect) {
		free (ret);
		return NULL;
	}

	r_buf_read_at (arch->buf, obj->header->sechdr_addr - obj->header->base,
		(ut8 *)sect, sizeof (xbe_section)*obj->header->sections);

	for (i = 0; i < obj->header->sections; i++) {
		RBinSection *item = R_NEW0(RBinSection);
		char tmp[0x100];

		r_buf_read_at (arch->buf, sect[i].name_addr - obj->header->base, (ut8 *)tmp, sizeof(tmp));

		snprintf(item->name, R_BIN_SIZEOF_STRINGS, "%s.%i", tmp, i);
		item->paddr = sect[i].offset;
		item->vaddr = sect[i].vaddr;
		item->size  = sect[i].size;
		item->vsize = sect[i].vsize;

		item->srwx |= 4;
		if (sect[i].flags & SECT_FLAG_X)
			item->srwx |= 1;
		if (sect[i].flags & SECT_FLAG_W)
			item->srwx |= 2;
		r_list_append (ret, item);
	}
	free (sect);

	return ret;
}

static RList* libs(RBinFile *arch) {
	r_bin_xbe_obj_t *obj;
	xbe_lib lib;
	RList *ret;
	char *s;
	int i, off;

	if (!arch || !arch->o)
		return NULL;
	obj = arch->o->bin_obj;
	ret = r_list_new ();
	if (!ret) return NULL;
	ret->free = free;
	if ( obj->header->kernel_lib_addr < obj->header->base) {
		off = 0;
	} else {
		off = obj->header->kernel_lib_addr - obj->header->base;
	}
	r_buf_read_at (arch->buf, off, (ut8 *)&lib, sizeof(xbe_lib));
	s = r_str_newf ("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
	if (s) r_list_append (ret, s);

	if ( obj->header->xapi_lib_addr < obj->header->base) {
		off = 0;
	} else {
		off = obj->header->xapi_lib_addr - obj->header->base;
	}
	r_buf_read_at (arch->buf, off, (ut8 *)&lib, sizeof(xbe_lib));
	s = r_str_newf ("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
	if (s) r_list_append (ret, s);

	for (i = 0; i < obj->header->lib_versions; i++) {
		r_buf_read_at (arch->buf, obj->header->lib_versions_addr - \
			obj->header->base + (i * sizeof (xbe_lib)),
			(ut8 *)&lib, sizeof (xbe_lib));
		s = r_str_newf ("%s %i.%i.%i", lib.name,
			lib.major, lib.minor, lib.build);
		if (s) r_list_append(ret, s);
	}

	return ret;
}

static RList* symbols(RBinFile *arch) {
	r_bin_xbe_obj_t *obj;
	RList *ret = r_list_new();
	int i, found = R_FALSE;
	ut32 thunk_addr[XBE_MAX_THUNK];
	ut32 kt_addr;
	xbe_section sect;

	if (!ret || !arch || !arch->o)
		return NULL;

	obj = arch->o->bin_obj;
	kt_addr = obj->header->kernel_thunk_addr ^ obj->kt_key;
	ret->free = free;

//eprintf ("VA %llx  %llx\n", sym->paddr, sym->vaddr);
	// PA -> VA translation
	for (i = 0; found == R_FALSE && i < obj->header->sections; i++) {
		r_buf_read_at (arch->buf, obj->header->sechdr_addr - \
			obj->header->base + (sizeof (xbe_section) * i), \
			(ut8 *)&sect, sizeof(sect));
		if (kt_addr >= sect.vaddr && kt_addr < sect.vaddr + sect.vsize)
			found = R_TRUE;
	}

	if (found == R_FALSE) {
		free (ret);
		return NULL;
	}

	r_buf_read_at (arch->buf, sect.offset + (kt_addr - sect.vaddr), \
		(ut8 *)&thunk_addr, sizeof (thunk_addr));
	for (i = 0; thunk_addr[i]; i++) {
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			ret->free(sym);
			return NULL;
		}

		const ut32 thunk_index = thunk_addr[i] ^ 0x80000000;

		// Basic sanity checks
		if (thunk_addr[i]&0x80000000 && thunk_index < XBE_MAX_THUNK) {
			snprintf(sym->name, R_BIN_SIZEOF_STRINGS, "kt.%s\n", kt_name[thunk_index]);
			sym->vaddr = (obj->header->kernel_thunk_addr ^ obj->kt_key) + (4 * i);
			sym->paddr = sym->vaddr - obj->header->base;
			sym->size = 4;
			sym->ordinal = i;
			r_list_append (ret, sym);
		} else free (sym);
	}
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	r_bin_xbe_obj_t *obj;
	RBinInfo *ret;
	ut8 dbg_name[256];

	if (!arch || !arch->buf)
		return NULL;

	ret = R_NEW0 (RBinInfo);
	if (!ret)
		return NULL;

	obj = arch->o->bin_obj;


	r_buf_read_at (arch->buf, obj->header->debug_name_addr - \
		obj->header->base, dbg_name, sizeof(dbg_name));
	strncpy (ret->file, (const char*)dbg_name, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->bclass, "program", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->machine, "Microsoft Xbox", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "xbox", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "Microsoft Xbox executable", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->lang = NULL;
	return ret;
}

static ut64 baddr(RBinFile *arch) {
	r_bin_xbe_obj_t *obj = arch->o->bin_obj;
	return obj->header->base;
}

struct r_bin_plugin_t r_bin_plugin_xbe = {
	.name = "xbe",
	.desc = "Microsoft Xbox xbe format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = NULL,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = NULL,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.relocs = NULL,
	.dbginfo = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_xbe
};
#endif
