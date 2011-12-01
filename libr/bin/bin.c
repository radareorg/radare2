/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

/* TODO:
 * dlopen library and show address
 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_list.h>
#include <r_bin.h>
#include <list.h>
#include "../config.h"

static RBinPlugin *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS };
static RBinXtrPlugin *bin_xtr_static_plugins[] = { R_BIN_XTR_STATIC_PLUGINS };

static void get_strings_range(RBinArch *arch, RList *list, int min, ut64 from, ut64 to, ut64 scnrva) {
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0;
	RBinString *ptr = NULL;

	if (to > arch->buf->length)
		to = arch->buf->length;
	for (i = from; i < to; i++) { 
		if ((IS_PRINTABLE (arch->buf->buf[i])) && matches < R_BIN_SIZEOF_STRINGS-1) {
			str[matches] = arch->buf->buf[i];
			matches++;
			continue;
		}
		/* check if the length fits in our request */
		if (matches >= min) {
			if (!(ptr = R_NEW (RBinString))) {
				eprintf ("Error allocating string\n");
				break;
			}
			str[matches] = '\0';
			ptr->offset = i-matches;
			ptr->rva = ptr->offset-from+scnrva;
			//HACK if (scnrva) ptr->rva = ptr->offset-from+scnrva; else ptr->rva = ptr->offset;
			ptr->size = matches+1;
			ptr->ordinal = ctr;
			// copying so many bytes here..
			memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
			ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
			r_name_filter (ptr->string, R_BIN_SIZEOF_STRINGS-1);
			r_list_append (list, ptr);
			ctr++;
		}
		matches = 0;
	}
}

static int is_data_section(RBinArch *a, RBinSection *s) {
	// XXX: DIRTY HACK! should we check sections srwx to be READ ONLY and NONEXEC?
	if (strstr (a->info->bclass, "MACH0") && strstr (s->name, "_cstring")) // OSX
		return 1;
	if (strstr (a->info->bclass, "ELF") && strstr (s->name, "data")) // LINUX
		return 1;
	if (strstr (a->info->bclass, "PE"))
		return 1;
	return 0;
}

// TODO: check only in data section. filter chars only in -r mode
static RList* get_strings(RBinArch *a, int min) {
	RBinSection *section;
	RListIter *iter;
	RList *ret;
	int count = 0;

	if (!(ret = r_list_new ())) {
		eprintf ("Error allocating array\n");
		return NULL;
	}
	ret->free = free;
	
	if (a->sections) {
		r_list_foreach (a->sections, iter, section) {
			if (is_data_section (a, section)) {
				count ++;
				get_strings_range (a, ret, min, 
					section->offset, section->offset+section->size, section->rva);
			}
		}	
	}
	if (r_list_empty (a->sections)) //if (count == 0)
		get_strings_range (a, ret, min, 0, a->size, 0);
	return ret;
}

static int r_bin_init_items(RBin *bin, int dummy) {
	int i;
	struct list_head *pos;
	RBinArch *a = &bin->curarch;

	a->curplugin = NULL;
	list_for_each (pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if ((dummy && !strncmp (h->name, "any", 5)) || 
			(!dummy && (h->check && h->check (&bin->curarch)))) {
			bin->curarch.curplugin = h;
			break;
		}
	}
	if (!a->curplugin || !a->curplugin->load || !a->curplugin->load (a))
		return R_FALSE;
	if (a->curplugin->baddr)
		a->baddr = a->curplugin->baddr (a);
	if (a->curplugin->binsym)
		for (i=0; i<R_BIN_SYM_LAST; i++)
			a->binsym[i] = a->curplugin->binsym (a, i);
	if (a->curplugin->entries)
		a->entries = a->curplugin->entries (a);
	if (a->curplugin->fields)
		a->fields = a->curplugin->fields (a);
	if (a->curplugin->imports)
		a->imports = a->curplugin->imports (a);
	if (a->curplugin->info)
		a->info = a->curplugin->info (a);
	if (a->curplugin->libs)
		a->libs = a->curplugin->libs (a);
	if (a->curplugin->relocs)
		a->relocs = a->curplugin->relocs (a);
	if (a->curplugin->sections)
		a->sections = a->curplugin->sections (a);
	if (a->curplugin->strings)
		a->strings = a->curplugin->strings (a);
	else a->strings = get_strings (a, 4);
	if (a->curplugin->symbols)
		a->symbols = a->curplugin->symbols (a);
	if (a->curplugin->classes)
		a->classes = a->curplugin->classes (a);
	return R_TRUE;
}

/* TODO: Free plugins */
static void r_bin_free_items(RBin *bin) {
	int i;
	RBinArch *a = &bin->curarch;
	// XXX: drop all those silly conditionals! if it's null is not for freeing
	if (a->entries) r_list_free (a->entries);
	if (a->fields) r_list_free (a->fields);
	if (a->imports) r_list_free (a->imports);
	if (a->info) free (a->info);
	if (a->libs) r_list_free (a->libs);
	if (a->relocs) r_list_free (a->relocs);
	if (a->sections) r_list_free (a->sections);
	if (a->strings) r_list_free (a->strings);
	if (a->symbols) r_list_free (a->symbols);
	if (a->binsym)
		for (i=0; i<R_BIN_SYM_LAST; i++)
			free (a->binsym[i]);
	if (a->file) free (a->file);
	if (a->curplugin && a->curplugin->destroy)
		a->curplugin->destroy (a);
}

static void r_bin_init(RBin *bin) {
	struct list_head *pos;

	bin->curxtr = NULL;
	list_for_each (pos, &bin->binxtrs) {
		RBinXtrPlugin *h = list_entry (pos, RBinXtrPlugin, list);
		if (h->check && h->check (bin)) {
			bin->curxtr = h;
			break;
		}
	}
	if (bin->curxtr && bin->curxtr->load)
		bin->curxtr->load (bin);
}

static int r_bin_extract(RBin *bin, int idx) {
	ut8 *buf;
	if (bin->curxtr && bin->curxtr->extract)
		return bin->curxtr->extract (bin, idx);
	//free (bin->curarch.file);
	bin->curarch.file = strdup (bin->file);
	if (!(buf = (ut8*)r_file_slurp (bin->file, &bin->curarch.size))) 
		return 0;
	bin->curarch.buf = r_buf_new ();
	if (!r_buf_set_bytes (bin->curarch.buf, buf, bin->curarch.size)) {
		free (buf);
		return 0;
	}
	free (buf);
	return 1;
}

R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	struct list_head *pos;
	if (foo->init)
		foo->init (bin->user);
	list_for_each_prev (pos, &bin->bins) { // XXX: use r_list here
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	list_add_tail (&(foo->list), &(bin->bins));
	return R_TRUE;
}

R_API int r_bin_xtr_add(RBin *bin, RBinXtrPlugin *foo) {
	struct list_head *pos;

	if (foo->init)
		foo->init (bin->user);
	list_for_each_prev (pos, &bin->binxtrs) {
		RBinXtrPlugin *h = list_entry (pos, RBinXtrPlugin, list);
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	list_add_tail (&(foo->list), &(bin->binxtrs));
	return R_TRUE;
}

R_API void* r_bin_free(RBin *bin) {
	if (!bin) return NULL;
	r_bin_free_items (bin);
	if (bin->curxtr && bin->curxtr->destroy)
		bin->curxtr->destroy (bin);
	free (bin);
	return NULL;
}

R_API int r_bin_list(RBin *bin) {
	struct list_head *pos;

	list_for_each_prev(pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		printf ("bin %-10s %s\n", h->name, h->desc);
	}
	list_for_each_prev(pos, &bin->binxtrs) {
		RBinXtrPlugin *h = list_entry (pos, RBinXtrPlugin, list);
		printf ("bin-xtr %-10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_bin_load(RBin *bin, const char *file, int dummy) {
	if (!bin || !file)
		return R_FALSE;
	bin->file = r_file_abspath (file);
	r_bin_init (bin);
	bin->narch = r_bin_extract (bin, 0);
	if (bin->narch == 0)
		return R_FALSE;
	return r_bin_init_items (bin, dummy);
}

// remove this getters.. we have no threads or mutexes to protect here
R_API ut64 r_bin_get_baddr(RBin *bin) {
	return bin->curarch.baddr;
}

R_API RBinAddr* r_bin_get_sym(RBin *bin, int sym) {
	if (sym<0 || sym>=R_BIN_SYM_LAST)
		return NULL;
	return bin->curarch.binsym[sym];
}

R_API RList* r_bin_get_entries(RBin *bin) {
	return bin->curarch.entries;
}

R_API RList* r_bin_get_fields(RBin *bin) {
	return bin->curarch.fields;
}

R_API RList* r_bin_get_imports(RBin *bin) {
	return bin->curarch.imports;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	return bin->curarch.info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	return bin->curarch.libs;
}

R_API RList* r_bin_get_relocs(RBin *bin) {
	return bin->curarch.relocs;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	return bin->curarch.sections;
}

R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	if (bin->curarch.sections)
	r_list_foreach (bin->curarch.sections, iter, section) {
		from = va ? bin->curarch.baddr+section->rva : section->offset;
		to = va ? bin->curarch.baddr+section->rva+section->vsize :
				  section->offset + section->size;
		if (off >= from && off < to)
			return section;
	}
	return NULL;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	return bin->curarch.strings;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	return bin->curarch.symbols;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	return bin->curarch.info->big_endian;
}

R_API int r_bin_is_stripped (RBin *bin) {
	return R_BIN_DBG_STRIPPED (bin->curarch.info->dbg_info);
}

R_API int r_bin_is_static (RBin *bin) {
	return R_BIN_DBG_STATIC (bin->curarch.info->dbg_info);
}

/* XXX Implement in r_bin_meta and deprecate? */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	return R_BIN_DBG_LINENUMS (bin->curarch.info->dbg_info);
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	return R_BIN_DBG_SYMS (bin->curarch.info->dbg_info);
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	return R_BIN_DBG_RELOCS (bin->curarch.info->dbg_info);
}

R_API RBin* r_bin_new() {
	int i;
	RBinPlugin *static_plugin;
	RBinXtrPlugin *static_xtr_plugin;
	RBin *bin = R_NEW (RBin);
	if (bin) {
		memset (bin, 0, sizeof (RBin));
		INIT_LIST_HEAD (&bin->bins);
		for (i=0; bin_static_plugins[i]; i++) {
			static_plugin = R_NEW (RBinPlugin);
			memcpy (static_plugin, bin_static_plugins[i], sizeof (RBinPlugin));
			r_bin_add (bin, static_plugin);
		}
		INIT_LIST_HEAD (&bin->binxtrs);
		for (i=0; bin_xtr_static_plugins[i]; i++) {
			static_xtr_plugin = R_NEW (RBinXtrPlugin);
			memcpy (static_xtr_plugin, bin_xtr_static_plugins[i], sizeof (RBinXtrPlugin));
			r_bin_xtr_add (bin, static_xtr_plugin);
		}
	}
	return bin;
}

// TODO: handle ARCH and BITS
/* arch and bits are implicit in the plugin name, do we really need
 * to overwrite bin->curarch.info? */
R_API int r_bin_use_arch(RBin *bin, const char *arch, int bits, const char *name) {
	struct list_head *pos;

	if (!bin->curarch.info)
		bin->curarch.info = R_NEW (RBinInfo);
	memset (bin->curarch.info, 0, sizeof (RBinInfo));
	strncpy (bin->curarch.info->arch, arch, R_BIN_SIZEOF_STRINGS);
	bin->curarch.info->bits = bits;

	list_for_each_prev(pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if (!strcmp (name, h->name)) {
			bin->curarch.curplugin = h;
// TODO: set bits and name
			return R_TRUE;
		}
	}
	return R_FALSE;
}

// DUPDUPDUP

R_API int r_bin_select(RBin *bin, const char *arch, int bits, const char *name) {
	int i;
	for (i=0; i<bin->narch; i++) {
		r_bin_select_idx (bin, i);
		if (!bin->curarch.info || !bin->curarch.file ||
			(arch && !strstr (bin->curarch.info->arch, arch)) ||
			(bits && bits != bin->curarch.info->bits) ||
			(name && !strstr (bin->curarch.file, name)))
			continue;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_bin_select_idx(RBin *bin, int idx) {
	r_bin_free_items (bin);
	if (r_bin_extract (bin, idx))
		return r_bin_init_items (bin, R_FALSE);
	return R_FALSE;
}

R_API void r_bin_list_archs(RBin *bin) {
	int i;
	for (i = 0; i < bin->narch; i++)
		if (r_bin_select_idx (bin, i) && bin->curarch.info)
			printf ("%03i 0x%08"PFMT64x" %s_%i %s\n", i, 
				bin->curarch.offset, bin->curarch.info->arch,
				bin->curarch.info->bits, bin->curarch.info->machine);
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}

static int getoffset (RBin *bin, int type, int idx) {
	RBinArch *a = &bin->curarch;
	if (a && a->curplugin && a->curplugin->get_offset)
		return a->curplugin->get_offset (a, type, idx);
	return -1;
}

R_API void r_bin_bind (RBin *bin, RBinBind *b) {
	b->bin = bin;
	b->get_offset = getoffset;
}

R_API RBuffer *r_bin_create (RBin *bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	RBinArch *a = &bin->curarch;
	if (codelen<0) codelen = 0;
	if (datalen<0) datalen = 0;
	if (a && a->curplugin && a->curplugin->create)
		return a->curplugin->create (bin, code, codelen, data, datalen);
	return NULL;
}

R_API RBinObj *r_bin_get_object(RBin *bin, int flags) {
	int i;
	RBinObj *obj = R_NEW (RBinObj);
	if (obj) {
		obj->symbols = r_bin_get_symbols (bin);
		obj->imports = r_bin_get_imports (bin);
		obj->entries = r_bin_get_entries (bin);
		for (i=0; i<R_BIN_SYM_LAST; i++)
			obj->binsym[i] = r_bin_get_sym (bin, i);
		obj->baddr = r_bin_get_baddr (bin);
		obj->info = r_bin_get_info (bin);
	}
	return obj;
}

R_API void r_bin_object_free(RBinObj *obj) {
	// XXX: leak
	free (obj);
}

R_API RList* /*<RBinClass>*/r_bin_get_classes(RBin *bin) {
	return bin->curarch.classes;
}

R_API ut64 r_bin_get_offset (RBin *bin) {
	ut64 offset = bin->curarch.offset;
	if (offset>0x1000) // XXX HACK
		offset -= 0x1000;
	return offset;
}
