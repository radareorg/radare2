/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

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

static void get_strings_range(RBin *bin, RList *list, int min, ut64 from, ut64 to) {
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0;
	RBinString *ptr = NULL;

	for(i = from; i < to; i++) { 
		if ((IS_PRINTABLE (bin->buf->buf[i])) && matches < R_BIN_SIZEOF_STRINGS-1) {
			str[matches] = bin->buf->buf[i];
			matches++;
		} else {
			/* check if the length fits in our request */
			if (matches >= min) {
				if (!(ptr = R_NEW (RBinString))) {
					eprintf ("Error allocating string\n");
					break;
				}
				str[matches] = '\0';
				ptr->rva = ptr->offset = i-matches;
				ptr->size = matches;
				ptr->ordinal = ctr;
				// copying so many bytes here..
				memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
				ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
				r_list_append (list, ptr);
				ctr++;
			}
			matches = 0;
		}
	}
}

// TODO: check only in data section. filter chars only in -r mode
static RList* get_strings(RBin *bin, int min) {
	RList *ret;
	int count = 0;

	if (!(ret = r_list_new ())) {
		eprintf ("Error allocating array\n");
		return NULL;
	}
	ret->free = free;
	
	if (bin->sections) {
		RBinSection *section;
		RListIter *iter;
		r_list_foreach (bin->sections, iter, section) {
			// XXX: should we check sections srwx to be READ ONLY and NONEXEC?
			if (strstr (section->name, "data")) {
				count ++;
				get_strings_range (bin, ret, min, 
					section->offset, section->offset+section->size);
			}
		}	
	}
	if (count == 0)
		get_strings_range (bin, ret, min, 0, bin->size);
	return ret;
}

static void r_bin_init_items(RBin *bin) {
	if (!bin->cur)
		return;
	if (bin->cur->baddr)
		bin->baddr = bin->cur->baddr (bin);
	if (bin->cur->main)
		bin->main = bin->cur->main (bin);
	if (bin->cur->entries)
		bin->entries = bin->cur->entries (bin);
	if (bin->cur->fields)
		bin->fields = bin->cur->fields (bin);
	if (bin->cur->imports)
		bin->imports = bin->cur->imports (bin);
	if (bin->cur->info)
		bin->info = bin->cur->info (bin);
	if (bin->cur->libs)
		bin->libs = bin->cur->libs (bin);
	if (bin->cur->sections)
		bin->sections = bin->cur->sections (bin);
	if (bin->cur->strings)
		bin->strings = bin->cur->strings (bin);
	else bin->strings = get_strings (bin, 4);
	if (bin->cur->symbols)
		bin->symbols = bin->cur->symbols (bin);
}

/* TODO: Free plugins */
static void r_bin_free_items(RBin *bin) {
	if (bin->entries)
		r_list_free (bin->entries);
	if (bin->fields)
		r_list_free (bin->fields);
	if (bin->imports)
		r_list_free (bin->imports);
	if (bin->info)
		free (bin->info);
	if (bin->libs)
		r_list_free (bin->libs);
	if (bin->sections)
		r_list_free (bin->sections);
	if (bin->strings)
		r_list_free (bin->strings);
	if (bin->symbols)
		r_list_free (bin->symbols);
}

R_API int r_bin_add(RBin *bin, RBinPlugin *foo) {
	struct list_head *pos;
	if (foo->init)
		foo->init (bin->user);
	list_for_each_prev (pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if (!strcmp (h->name, foo->name))
			return R_FALSE;
	}
	list_add_tail (&(foo->list), &(bin->bins));
	return R_TRUE;
}

R_API void* r_bin_free(RBin *bin) {
	if (!bin)
		return NULL;
	r_bin_free_items (bin);
	if (bin->cur && bin->cur->destroy)
		bin->cur->destroy (bin);
	free (bin);
	return NULL;
}

R_API int r_bin_list(RBin *bin) {
	struct list_head *pos;

	list_for_each_prev(pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		printf ("bin %-10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_bin_load(RBin *bin, const char *file, const char *plugin_name) {
	struct list_head *pos;
	if (!bin || !file)
		return R_FALSE;
	bin->file = r_file_abspath (file);
	bin->cur = NULL;
	list_for_each (pos, &bin->bins) {
		RBinPlugin *h = list_entry (pos, RBinPlugin, list);
		if ((plugin_name && !strcmp (h->name, plugin_name)) ||
				(h->check && h->check (bin)))
			bin->cur = h;
	}
	if (bin->cur && bin->cur->load && bin->cur->load (bin))
		r_bin_init_items (bin);
	else return R_FALSE;
	return R_TRUE;
}

// remove this getters.. we have no threads or mutexes to protect here
R_API ut64 r_bin_get_baddr(RBin *bin) {
	return bin->baddr;
}

R_API RBinAddr* r_bin_get_main(RBin *bin) {
	return bin->main;
}

R_API RList* r_bin_get_entries(RBin *bin) {
	return bin->entries;
}

R_API RList* r_bin_get_fields(RBin *bin) {
	return bin->fields;
}

R_API RList* r_bin_get_imports(RBin *bin) {
	return bin->imports;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	return bin->info;
}

R_API RList* r_bin_get_libs(RBin *bin) {
	return bin->libs;
}

R_API RList* r_bin_get_sections(RBin *bin) {
	return bin->sections;
}

R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off, int va) {
	RBinSection *section;
	RListIter *iter;
	ut64 from, to;

	if (bin->sections)
	r_list_foreach (bin->sections, iter, section) {
		from = va ? bin->baddr+section->rva : section->offset;
		to = va ? bin->baddr+section->rva+section->vsize :
				  section->offset + section->size;
		if (off >= from && off < to)
			return section;
	}
	return NULL;
}

R_API RList* r_bin_get_strings(RBin *bin) {
	return bin->strings;
}

R_API RList* r_bin_get_symbols(RBin *bin) {
	return bin->symbols;
}

R_API int r_bin_is_big_endian (RBin *bin) {
	return bin->info->big_endian;
}

R_API int r_bin_is_stripped (RBin *bin) {
	return R_BIN_DBG_STRIPPED (bin->info->dbg_info);
}

R_API int r_bin_is_static (RBin *bin) {
	return R_BIN_DBG_STATIC (bin->info->dbg_info);
}

/* XXX Implement in r_bin_meta and deprecate? */
R_API int r_bin_has_dbg_linenums (RBin *bin) {
	return R_BIN_DBG_LINENUMS (bin->info->dbg_info);
}

R_API int r_bin_has_dbg_syms (RBin *bin) {
	return R_BIN_DBG_SYMS (bin->info->dbg_info);
}

R_API int r_bin_has_dbg_relocs (RBin *bin) {
	return R_BIN_DBG_RELOCS (bin->info->dbg_info);
}

R_API RBin* r_bin_new() {
	RBin *bin; 
	RBinPlugin *static_plugin;
	int i;

	bin = R_NEW (RBin);
	if (bin) {
		memset (bin, 0, sizeof(RBin));
		INIT_LIST_HEAD (&bin->bins);
		for (i=0;bin_static_plugins[i];i++) {
			static_plugin = R_NEW (RBinPlugin);
			memcpy (static_plugin, bin_static_plugins[i], sizeof (RBinPlugin));
			r_bin_add (bin, static_plugin);
		}
	}
	return bin;
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}
