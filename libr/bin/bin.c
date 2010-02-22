/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

/* TODO:
 * Linked libraries
 * dlopen library and show address
 */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../config.h"

/* plugin pointers */
extern RBinHandle r_bin_plugin_elf;
extern RBinHandle r_bin_plugin_elf64;
extern RBinHandle r_bin_plugin_pe;
extern RBinHandle r_bin_plugin_pe64;
extern RBinHandle r_bin_plugin_mach0;
extern RBinHandle r_bin_plugin_java;
extern RBinHandle r_bin_plugin_dummy;

static RBinHandle *bin_static_plugins[] = { R_BIN_STATIC_PLUGINS };

static RFList get_strings(RBin *bin, int min) {
	RFList ret;
	RBinString *ptr = NULL;
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0, max_str = 0;

	max_str = (int)(bin->size/min);
	if (!(ret = r_flist_new (max_str))) {
		eprintf ("Error allocating array\n");
		return NULL;
	}
	for(i = 0; i < bin->size && ctr < max_str; i++) { 
		if ((IS_PRINTABLE (bin->buf->buf[i])) && matches < R_BIN_SIZEOF_STRINGS-1) {
				str[matches] = bin->buf->buf[i];
				matches++;
		} else {
			/* check if the length fits on our request */
			if (matches >= min) {
				if (!(ptr = MALLOC_STRUCT (RBinString))) {
					fprintf(stderr, "Error allocating string\n");
					break;
				}
				str[matches] = '\0';
				ptr->rva = ptr->offset = i-matches;
				ptr->size = matches;
				ptr->ordinal = ctr;
				memcpy (ptr->string, str, R_BIN_SIZEOF_STRINGS);
				ptr->string[R_BIN_SIZEOF_STRINGS-1] = '\0';
				r_flist_set (ret, ctr, ptr);
				ctr++;
			}
			matches = 0;
		}
	}
	return ret;
}

static void r_bin_init_items(RBin *bin) {
	if (!bin->cur)
		return;
	if (bin->cur->baddr)
		bin->baddr = bin->cur->baddr (bin);
	if (bin->cur->entries)
		bin->entries = bin->cur->entries (bin);
	if (bin->cur->fields)
		bin->fields = bin->cur->fields (bin);
	if (bin->cur->imports)
		bin->imports = bin->cur->imports (bin);
	if (bin->cur->info)
		bin->info = bin->cur->info (bin);
	if (bin->cur->sections)
		bin->sections = bin->cur->sections (bin);
	if (bin->cur->strings)
		bin->strings = bin->cur->strings (bin);
	else bin->strings = get_strings (bin, 5);
	if (bin->cur->symbols)
		bin->symbols = bin->cur->symbols (bin);
}

static void r_bin_free_items(RBin *bin) {
	if (bin->entries)
		r_flist_free (bin->entries);
	if (bin->fields)
		r_flist_free (bin->fields);
	if (bin->imports)
		r_flist_free (bin->imports);
	if (bin->info)
		free (bin->info);
	if (bin->sections)
		r_flist_free (bin->sections);
	if (bin->strings)
		r_flist_free (bin->strings);
	if (bin->symbols)
		r_flist_free (bin->symbols);
}

R_API int r_bin_add(RBin *bin, RBinHandle *foo) {
	struct list_head *pos;
	if (foo->init)
		foo->init (bin->user);
	list_for_each_prev (pos, &bin->bins) {
		RBinHandle *h = list_entry (pos, RBinHandle, list);
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
	free(bin);
	return NULL;
}

R_API int r_bin_init(RBin *bin) {
	int i;

	memset (bin, 0, sizeof(RBin));
	INIT_LIST_HEAD (&bin->bins);
	for(i=0;bin_static_plugins[i];i++)
		r_bin_add (bin, bin_static_plugins[i]);
	return R_TRUE;
}

R_API int r_bin_list(RBin *bin) {
	struct list_head *pos;

	list_for_each_prev(pos, &bin->bins) {
		RBinHandle *h = list_entry (pos, RBinHandle, list);
		printf ("bin %-10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API int r_bin_load(RBin *bin, const char *file, const char *plugin_name) {
	struct list_head *pos;

	if (!bin || !file)
		return R_FALSE;
	bin->file = r_file_abspath (file);
	list_for_each_prev (pos, &bin->bins) {
		RBinHandle *h = list_entry (pos, RBinHandle, list);
		if ((plugin_name && !strcmp (h->name, plugin_name)) ||
			(h->check && h->check (bin))) 
			bin->cur = h;
	}
	if (bin->cur && bin->cur->load && bin->cur->load (bin))
		r_bin_init_items (bin);
	else return R_FALSE;
	return R_TRUE;
}


R_API ut64 r_bin_get_baddr(RBin *bin) {
	return bin->baddr;
}

R_API RFList r_bin_get_entries(RBin *bin) {
	return bin->entries;
}

R_API RFList r_bin_get_fields(RBin *bin) {
	return bin->fields;
}

R_API RFList r_bin_get_imports(RBin *bin) {
	return bin->imports;
}

R_API RBinInfo* r_bin_get_info(RBin *bin) {
	return bin->info;
}

R_API RFList r_bin_get_libs(RBin *bin) {
	return bin->libs;
}

R_API RFList r_bin_get_sections(RBin *bin) {
	return bin->sections;
}

#if 0
R_API RBinSection* r_bin_get_section_at(RBin *bin, ut64 off) {
	/* TODO */
}
#endif

R_API RFList r_bin_get_strings(RBin *bin) {
	return bin->strings;
}

R_API RFList r_bin_get_symbols(RBin *bin) {
	return bin->symbols;
}

R_API RBin* r_bin_new() {
	RBin *bin; 

	if (!(bin = MALLOC_STRUCT (RBin)))
		return NULL;
	r_bin_init (bin);
	return bin;
}

R_API void r_bin_set_user_ptr(RBin *bin, void *user) {
	bin->user = user;
}
