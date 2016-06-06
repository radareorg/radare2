/* radare - LGPL - 2014-2015 - thatlemon@gmail.com, pancake */

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
		return false;

	return check_bytes(bytes, size);
}

static int load(RBinFile *arch) {
	r_bin_xbe_obj_t *obj = NULL;
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	if (!arch || !arch->o)
		return false;
	arch->o->bin_obj = malloc (sizeof (r_bin_plugin_xbe));
	if (!arch->o->bin_obj)
		return false;
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
		return true;
	}

	return false;
}

static int destroy(RBinFile *arch) {
	free(arch->o->bin_obj);
	r_buf_free (arch->buf);
	arch->buf = NULL;
	arch->o->bin_obj = NULL;
	return true;
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
	xbe_section *sect = NULL;
	r_bin_xbe_obj_t *obj = NULL;
	xbe_header *h = NULL;
	RList *ret = NULL;
	char tmp[0x100];
	int i, r;
	ut32 addr;

	if (!arch || !arch->o || !arch->o->bin_obj || !arch->buf) 
		return NULL;
	obj = arch->o->bin_obj;
	h = obj->header;
	if (h->sections < 1)
		return NULL;
	ret = r_list_new ();
	if (!ret)
		return NULL;
	ret->free = free;
	if (h->sections < 1 || h->sections > 255)
		goto out_error;
	sect = calloc (h->sections, sizeof (xbe_section));
	if (!sect)
		goto out_error;
	addr = h->sechdr_addr - h->base;
	if (addr > arch->size || addr + (sizeof(xbe_section) * h->sections) > arch->size)
		goto out_error;
	r = r_buf_read_at (arch->buf, addr, (ut8 *)sect, sizeof(xbe_section) * h->sections);
	if (r < 1)
		goto out_error;
	for (i = 0; i < h->sections; i++) {
		RBinSection *item = R_NEW0(RBinSection);
		addr = sect[i].name_addr - h->base;
		tmp[0] = 0;
		if (addr > arch->size || addr + sizeof (tmp) > arch->size) {
			free (item);
			goto out_error;
		}
		r = r_buf_read_at (arch->buf, addr, (ut8 *)tmp, sizeof (tmp));
		if (r < 1) {
			free (item);
			goto out_error;
		}
		tmp[sizeof (tmp) - 1] = 0;
		snprintf (item->name, R_BIN_SIZEOF_STRINGS, "%s.%i", tmp, i);
		item->paddr = sect[i].offset;
		item->vaddr = sect[i].vaddr;
		item->size  = sect[i].size;
		item->vsize = sect[i].vsize;
		item->add = true;

		item->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP;
		if (sect[i].flags & SECT_FLAG_X)
			item->srwx |= R_BIN_SCN_EXECUTABLE;
		if (sect[i].flags & SECT_FLAG_W)
			item->srwx |= R_BIN_SCN_WRITABLE;
		r_list_append (ret, item);
	}
	free (sect);
	return ret;
out_error:
	r_list_free (ret);
	free (sect);
	return NULL;
}

static RList* libs(RBinFile *arch) {
	r_bin_xbe_obj_t *obj;
	xbe_header *h = NULL;
	int i, off, libs, r;
	xbe_lib lib;
	RList *ret;
	char *s;
	ut32 addr;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;
	obj = arch->o->bin_obj;
	h = obj->header;
	ret = r_list_new ();
	if (!ret)
		return NULL;
	ret->free = free;
	if (h->kernel_lib_addr < h->base)
		off = 0;
	else
		off = h->kernel_lib_addr - h->base;
	if (off > arch->size || off + sizeof(xbe_lib) > arch->size)
		goto out_error;
	r = r_buf_read_at (arch->buf, off, (ut8 *)&lib, sizeof(xbe_lib));
	if (r < 1)
		goto out_error;
	lib.name[7] = 0;
	s = r_str_newf ("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
	if (s)
		r_list_append (ret, s);
	if (h->xapi_lib_addr < h->base)
		off = 0;
	else
		off = h->xapi_lib_addr - h->base;
	if (off > arch->size || off + sizeof(xbe_lib) > arch->size)
		goto out_error;
	r = r_buf_read_at (arch->buf, off, (ut8 *)&lib, sizeof(xbe_lib));
	if (r < 1)
		goto out_error;

	lib.name[7] = 0;
	s = r_str_newf ("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
	if (s)
		r_list_append (ret, s);
	libs = h->lib_versions;
	if (libs < 1)
		goto out_error;
	for (i = 0; i < libs; i++) {
		addr = h->lib_versions_addr - h->base + (i * sizeof (xbe_lib));
		if (addr > arch->size || addr + sizeof (xbe_lib) > arch->size)
			goto out_error;
		r = r_buf_read_at (arch->buf, addr, (ut8 *)&lib, sizeof (xbe_lib));
		if (r < 1)
			goto out_error;
		//make sure it ends with 0
		lib.name[7] = '\0';
		s = r_str_newf ("%s %i.%i.%i", lib.name, lib.major, lib.minor, lib.build);
		if (s)
			r_list_append(ret, s);
	}

	return ret;
out_error:
	r_list_free (ret);
	return NULL;
}

static RList* symbols(RBinFile *arch) {
	r_bin_xbe_obj_t *obj;
	xbe_header *h;
	RList *ret;
	int i, found = false;
	ut32 thunk_addr[XBE_MAX_THUNK];
	ut32 kt_addr;
	xbe_section sect;
	ut32 addr;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;

	obj = arch->o->bin_obj;
	h = obj->header;
	kt_addr = h->kernel_thunk_addr ^ obj->kt_key;
	ret = r_list_new();
	if (!ret)
		return NULL;
	ret->free = free;
	eprintf ("sections %d\n", h->sections);
	int limit = h->sections;
	if (limit * (sizeof(xbe_section)) >= arch->size - h->sechdr_addr)
		goto out_error;
	for (i = 0; found == false && i < limit; i++) {
		addr = h->sechdr_addr - h->base + (sizeof (xbe_section) * i);
		if (addr > arch->size || addr + sizeof(sect) > arch->size)
			goto out_error;
		r_buf_read_at (arch->buf, addr, (ut8 *)&sect, sizeof(sect));
		if (kt_addr >= sect.vaddr && kt_addr < sect.vaddr + sect.vsize)
			found = true;
	}
	if (!found)
		goto out_error;
	addr = sect.offset + (kt_addr - sect.vaddr);
	if (addr > arch->size || addr + sizeof(thunk_addr) > arch->size)
		goto out_error;
	i = r_buf_read_at (arch->buf, addr, (ut8 *)&thunk_addr, sizeof (thunk_addr));
	if (i != sizeof (thunk_addr))
		goto out_error;
	for (i = 0; i < XBE_MAX_THUNK && thunk_addr[i]; i++) {
		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym)
			goto out_error;
		const ut32 thunk_index = thunk_addr[i] ^ 0x80000000;
		// Basic sanity checks
		if (thunk_addr[i] & 0x80000000 && thunk_index < XBE_MAX_THUNK) {
			eprintf ("%d\n", thunk_index);
			sym->name = r_str_newf ("kt.%s", kt_name[thunk_index]);
			sym->vaddr = (h->kernel_thunk_addr ^ obj->kt_key) + (4 * i);
			sym->paddr = sym->vaddr - h->base;
			sym->size = 4;
			sym->ordinal = i;
			r_list_append (ret, sym);
		} else {
			free (sym);
		}
	}
	return ret;
out_error:
	r_list_free (ret);
	return NULL;
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

	memset (dbg_name, 0, sizeof (dbg_name));
	r_buf_read_at (arch->buf, obj->header->debug_name_addr - \
		obj->header->base, dbg_name, sizeof (dbg_name));
	dbg_name[sizeof(dbg_name)-1] = 0;
	ret->file = strdup ((char *)dbg_name);
	ret->bclass = strdup ("program");
	ret->machine = strdup ("Microsoft Xbox");
	ret->os = strdup ("xbox");
	ret->type = strdup ("Microsoft Xbox executable");
	ret->arch = strdup ("x86");
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
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.libs = &libs,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_xbe,
	.version = R2_VERSION
};
#endif
