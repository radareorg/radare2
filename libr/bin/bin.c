/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

/* TODO:
 * Linked libraries
 * dlopen library and show address
 * Strings
 * XRefs
 * Generic resize
 */

#include <stdio.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../config.h"

static struct r_bin_handle_t *bin_static_plugins[] = 
	{ R_BIN_STATIC_PLUGINS };

static struct r_bin_string_t *get_strings(struct r_bin_t *bin, int min)
{
	struct r_bin_string_t *ret = NULL;
	ut8 *buf = NULL;
	ut64 len, max_str = 0;
	int i, matches = 0, ctr = 0;
	char str[R_BIN_SIZEOF_STRINGS];

	len = lseek(bin->fd, 0, SEEK_END);
	max_str = (ut64)(len/min);

	ret = malloc(max_str*sizeof(struct r_bin_string_t));

	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "Error allocating file\n");
		return NULL;
	}
	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, len);

	for(i = 0; i < len && ctr < max_str; i++) { 
		if ((IS_PRINTABLE(buf[i]))) {
			str[matches] = buf[i];
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

	free(buf);

	return ret;
}

struct r_bin_t *r_bin_new()
{
	struct r_bin_t *bin = MALLOC_STRUCT(struct r_bin_t);
	r_bin_init(bin);
	return bin;
}

void r_bin_free(struct r_bin_t *bin)
{
	free(bin);
}

int r_bin_init(struct r_bin_t *bin)
{
	int i;
	bin->cur = NULL;
	bin->user = NULL;
	bin->file = NULL;
	bin->rw = 0;
	INIT_LIST_HEAD(&bin->bins);
	for(i=0;bin_static_plugins[i];i++)
		r_bin_add(bin, bin_static_plugins[i]);
	return R_TRUE;
}

void r_bin_set_user_ptr(struct r_bin_t *bin, void *user)
{
	bin->user = user;
}

int r_bin_add(struct r_bin_t *bin, struct r_bin_handle_t *foo)
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

int r_bin_list(struct r_bin_t *bin)
{
	struct list_head *pos;
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		printf(" %s: %s\n", h->name, h->desc);
	}
	return R_FALSE;
}

int r_bin_open(struct r_bin_t *bin, const char *file, int rw, char *plugin_name)
{
	if (file != NULL)
		bin->file = file;
	else return -1;
	bin->rw = rw;

	struct list_head *pos;
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		if ((plugin_name && !strcmp(h->name, plugin_name)) ||
			(h->check && h->check(bin))) 
			bin->cur = h;
	}

	if (bin->cur && bin->cur->open)
		return bin->cur->open(bin);
	if (plugin_name && !strcmp(plugin_name, "bin_dummy"))
		return -1;
	return r_bin_open(bin, file, rw, "bin_dummy");
}

int r_bin_close(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->close)
		return bin->cur->close(bin);
	
	return -1;
}

ut64 r_bin_get_baddr(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->baddr)
		return bin->cur->baddr(bin);
	
	return -1;
}

struct r_bin_entry_t* r_bin_get_entry(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->entry)
		return bin->cur->entry(bin);
	
	return NULL;
}

struct r_bin_section_t* r_bin_get_sections(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->sections)
		return bin->cur->sections(bin);
	
	return NULL;
}

struct r_bin_symbol_t* r_bin_get_symbols(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->symbols)
		return bin->cur->symbols(bin);
	
	return NULL;
}

struct r_bin_import_t* r_bin_get_imports(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->imports)
		return bin->cur->imports(bin);
	
	return NULL;
}

struct r_bin_string_t* r_bin_get_strings(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->strings)
		return bin->cur->strings(bin);
	else return get_strings(bin, 5);
	
	return NULL;
}

struct r_bin_info_t* r_bin_get_info(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->info)
		return bin->cur->info(bin);
	
	return NULL;
}

struct r_bin_field_t* r_bin_get_fields(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->fields)
		return bin->cur->fields(bin);
	
	return NULL;
}

ut64 r_bin_get_section_offset(struct r_bin_t *bin, char *name)
{
	struct r_bin_section_t *sections;
	ut64 ret = -1;
	int i;

	if (!(sections = r_bin_get_sections(bin)))
		return R_FALSE;

	for (i = 0; !sections[i].last; i++)
		if (!strcmp(sections[i].name, name)) {
			ret = sections[i].offset;
			break;
		}

	free(sections);

	return ret;
}

ut64 r_bin_get_section_rva(struct r_bin_t *bin, char *name)
{
	struct r_bin_section_t *sections;
	ut64 ret = -1;
	int i;

	if (!(sections = r_bin_get_sections(bin)))
		return R_FALSE;

	for (i = 0; !sections[i].last; i++) {
		if (!strcmp(sections[i].name, name)) {
			ret = sections[i].rva;
			break;
		}
	}

	free(sections);

	return ret;
}

ut64 r_bin_get_section_size(struct r_bin_t *bin, char *name)
{
	struct r_bin_section_t *sections;
	ut64 ret = -1;
	int i;

	if (!(sections = r_bin_get_sections(bin)))
		return R_FALSE;

	for (i = 0; !sections[i].last; i++) {
		if (!strcmp(sections[i].name, name)) {
			ret = sections[i].size;
			break;
		}
	}

	free(sections);

	return ret;
}

#if 0
int r_bin_get_libs()
{

}
#endif
