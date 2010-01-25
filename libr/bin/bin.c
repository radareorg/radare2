/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

/* TODO:
 * Linked libraries
 * dlopen library and show address
 * XRefs
 * Generic resize
 */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../config.h"

/* plugin pointers */
extern struct r_bin_handle_t r_bin_plugin_elf;
extern struct r_bin_handle_t r_bin_plugin_elf64;
extern struct r_bin_handle_t r_bin_plugin_pe;
extern struct r_bin_handle_t r_bin_plugin_pe64;
extern struct r_bin_handle_t r_bin_plugin_mach0;
extern struct r_bin_handle_t r_bin_plugin_java;
extern struct r_bin_handle_t r_bin_plugin_dummy;

static struct r_bin_handle_t *bin_static_plugins[] = 
	{ R_BIN_STATIC_PLUGINS };

static struct r_bin_string_t *get_strings(struct r_bin_t *bin, int min)
{
	struct r_bin_string_t *ret = NULL;
	char str[R_BIN_SIZEOF_STRINGS];
	int i, matches = 0, ctr = 0, max_str = 0;

	max_str = (int)(bin->size/min);
	ret = malloc(max_str*sizeof(struct r_bin_string_t));
	if (ret == NULL) {
		fprintf(stderr, "Error allocating file\n");
		return NULL;
	}
	for(i = 0; i < bin->size && ctr < max_str; i++) { 
		if ((IS_PRINTABLE(bin->buf->buf[i]))) {
			str[matches] = bin->buf->buf[i];
			if (matches < sizeof(str))
				matches++;
		} else {
			/* check if the length fits on our request */
			if (matches >= min) {
				str[matches] = '\0';
				ret[ctr].rva = ret[ctr].offset = i-matches;
				ret[ctr].size = matches;
				ret[ctr].ordinal = ctr;
				memcpy(ret[ctr].string, str, R_BIN_SIZEOF_STRINGS);
				ret[ctr].string[R_BIN_SIZEOF_STRINGS-1] = '\0';
				ret[ctr].last = 0;
				ctr++;
			}
			matches = 0;
		}
	}
	ret[ctr].last = 1;
	return ret;
}

R_API int r_bin_add(struct r_bin_t *bin, struct r_bin_handle_t *foo)
{
	struct list_head *pos;
	if (foo->init)
		foo->init(bin->user);
	/* avoid dupped plugins */
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		if (!strcmp(h->name, foo->name))
			return R_FALSE;
	}
	list_add_tail(&(foo->list), &(bin->bins));
	return R_TRUE;
}

R_API void* r_bin_free(struct r_bin_t *bin)
{
	if (!bin)
		return NULL;
	if (bin->cur && bin->cur->free)
		bin->cur->free(bin);
	free(bin);
	return NULL;
}

R_API void* r_bin_free_obj(struct r_bin_obj_t *binobj)
{
	if (!binobj)
		return NULL;
	/* TODO: free r_bin_obj_t structures */
	free(binobj);
	return NULL;
}

R_API int r_bin_init(struct r_bin_t *bin)
{
	int i;

	bin->cur = bin->user = NULL;
	bin->file = NULL;
	bin->size = 0;
	INIT_LIST_HEAD(&bin->bins);
	for(i=0;bin_static_plugins[i];i++)
		r_bin_add(bin, bin_static_plugins[i]);
	return R_TRUE;
}

R_API int r_bin_list(struct r_bin_t *bin)
{
	struct list_head *pos;

	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		printf("bin %-10s %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API struct r_bin_obj_t *r_bin_load(struct r_bin_t *bin, const char *file, const char *plugin_name)
{
	struct r_bin_obj_t *binobj = NULL;
	struct list_head *pos;

	if (!bin || !file)
		return NULL;
	if (!(binobj = MALLOC_STRUCT(struct r_bin_obj_t)))
		return NULL;
	bin->file = file;
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		if ((plugin_name && !strcmp(h->name, plugin_name)) ||
			(h->check && h->check(bin))) 
			bin->cur = h;
	}
	if (bin->cur && bin->cur->new)
		bin->cur->new(bin);
	else return NULL;
	/* TODO: allocate and fill r_bin_obj */
	return binobj;
}


R_API ut64 r_bin_get_baddr(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->baddr)
		return bin->cur->baddr(bin);
	return UT64_MAX;
}

R_API struct r_bin_entry_t* r_bin_get_entry(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->entry)
		return bin->cur->entry(bin);
	return NULL;
}

R_API struct r_bin_field_t* r_bin_get_fields(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->fields)
		return bin->cur->fields(bin);
	return NULL;
}

R_API struct r_bin_import_t* r_bin_get_imports(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->imports)
		return bin->cur->imports(bin);
	return NULL;
}

R_API struct r_bin_info_t* r_bin_get_info(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->info)
		return bin->cur->info(bin);
	return NULL;
}

R_API struct r_bin_section_t* r_bin_get_sections(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->sections)
		return bin->cur->sections(bin);
	return NULL;
}

R_API struct r_bin_string_t* r_bin_get_strings(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->strings)
		return bin->cur->strings(bin);
	return get_strings(bin, 5);
}

R_API struct r_bin_symbol_t* r_bin_get_symbols(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->symbols)
		return bin->cur->symbols(bin);
	return NULL;
}

#if 0
int r_bin_get_libs()
{

}
#endif

R_API struct r_bin_t* r_bin_new()
{
	struct r_bin_t *bin; 

	if (!(bin = MALLOC_STRUCT(struct r_bin_t)))
		return NULL;
	r_bin_init(bin);
	return bin;
}

R_API void r_bin_set_user_ptr(struct r_bin_t *bin, void *user)
{
	bin->user = user;
}
