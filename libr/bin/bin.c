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
	ut8 *buf = NULL;
	ut64 len, max_str = 0;
	int i, matches = 0, ctr = 0;
	char str[R_BIN_SIZEOF_STRINGS];

	len = lseek(bin->fd, 0, SEEK_END);
	max_str = (ut64)(len/min);

	ret = malloc(max_str*sizeof(struct r_bin_string_t));
	if (ret == NULL) {
		fprintf(stderr, "Error allocating file\n");
		return NULL;
	}

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

R_API struct r_bin_t *r_bin_new()
{
	struct r_bin_t *bin = MALLOC_STRUCT(struct r_bin_t);
	if (bin != NULL)
		r_bin_init(bin);
	return bin;
}

R_API struct r_bin_t *r_bin_free(struct r_bin_t *bin)
{
	free(bin);
	return NULL;
}

static int r_bin_io_read_at(struct r_io_t *io, ut64 addr, ut8 *buf, int size)
{
	// TODO: Implement this
	return size;
}

static int r_bin_io_write_at(struct r_io_bind_t *io, ut64 addr, const ut8 *buf, int size)
{
	// TODO: Implement this
	return size;
}
static void r_bin_io_init(struct r_bin_t *bin)
{
	bin->iob.init = R_TRUE;
	bin->iob.io = NULL;
	bin->iob.read_at = r_bin_io_read_at;
	bin->iob.write_at = (void*)r_bin_io_write_at;
}

R_API int r_bin_init(struct r_bin_t *bin)
{
	int i;
	bin->rw = 0;
	bin->cur = bin->user = NULL;
	bin->file = NULL;
	INIT_LIST_HEAD(&bin->bins);
	for(i=0;bin_static_plugins[i];i++)
		r_bin_add(bin, bin_static_plugins[i]);
	r_bin_io_init(bin);
	return R_TRUE;
}

// TODO: why the hell do we need user ptr here??
R_API void r_bin_set_user_ptr(struct r_bin_t *bin, void *user)
{
	bin->user = user;
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

R_API int r_bin_list(struct r_bin_t *bin)
{
	struct list_head *pos;
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		printf("bin %s\t%s\n", h->name, h->desc);
	}
	return R_FALSE;
}

R_API struct r_bin_object_t *r_bin_load(struct r_bin_t *bin, const char *file, const char *plugin_name)
{
	int fd = r_bin_open (bin, file, R_FALSE, plugin_name);
	if (fd == -1)
		return NULL;
	/* TODO: allocate and fill r_bin_object */
	r_bin_close (bin);
	return NULL;
}

R_API int r_bin_open(struct r_bin_t *bin, const char *file, int rw, const char *plugin_name)
{
	struct list_head *pos;

	if (bin == NULL || file == NULL)
		return -1;
	bin->file = file;
	bin->rw = rw;
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		if ((plugin_name && !strcmp(h->name, plugin_name)) ||
			(h->check && h->check(bin))) 
			bin->cur = h;
	}
	if (bin->cur && bin->cur->open)
		return bin->cur->open(bin);
	if (plugin_name && !strcmp(plugin_name, "dummy"))
		return -1;
	return r_bin_open(bin, file, rw, "dummy");
}

R_API int r_bin_close(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->close)
		return bin->cur->close(bin);
	return -1;
}

R_API ut64 r_bin_get_baddr(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->baddr)
		return bin->cur->baddr(bin);
	return UT64_MAX;
}

/* XXX : a binary can contain more than one entrypoint */
R_API struct r_bin_entry_t* r_bin_get_entry(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->entry)
		return bin->cur->entry(bin);
	return NULL;
}

R_API struct r_bin_section_t* r_bin_get_sections(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->sections)
		return bin->cur->sections(bin);
	return NULL;
}

R_API struct r_bin_symbol_t* r_bin_get_symbols(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->symbols)
		return bin->cur->symbols(bin);
	return NULL;
}

R_API struct r_bin_import_t* r_bin_get_imports(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->imports)
		return bin->cur->imports(bin);
	return NULL;
}

R_API struct r_bin_string_t* r_bin_get_strings(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->strings)
		return bin->cur->strings(bin);
	return get_strings(bin, 5);
}

R_API struct r_bin_info_t* r_bin_get_info(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->info)
		return bin->cur->info(bin);
	return NULL;
}

R_API struct r_bin_field_t* r_bin_get_fields(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->fields)
		return bin->cur->fields(bin);
	return NULL;
}

// why not just return a single instance of the Section struct?
R_API ut64 r_bin_get_section_offset(struct r_bin_t *bin, const char *name)
{
	struct r_bin_section_t *sections;
	ut64 ret = UT64_MAX;
	int i;

	sections = r_bin_get_sections(bin);
	if (sections) {
		for (i = 0; !sections[i].last; i++)
			if (!strcmp(sections[i].name, name)) {
				ret = sections[i].offset;
				break;
			}
		free(sections);
	}
	return ret;
}

R_API ut64 r_bin_get_section_rva(struct r_bin_t *bin, const char *name)
{
	struct r_bin_section_t *sections;
	ut64 ret = UT64_MAX;
	int i;

	sections = r_bin_get_sections(bin);
	if (sections) {
		for (i=0; !sections[i].last; i++) {
			if (!strcmp(sections[i].name, name)) {
				ret = sections[i].rva;
				break;
			}
		}
		free(sections);
	}
	return ret;
}

R_API ut64 r_bin_get_section_size(struct r_bin_t *bin, const char *name)
{
	struct r_bin_section_t *sections;
	ut64 ret = UT64_MAX;
	int i;

	sections = r_bin_get_sections(bin);
	if (sections) {
		for (i=0; !sections[i].last; i++) {
			if (!strcmp(sections[i].name, name)) {
				ret = sections[i].size;
				break;
			}
		}
		free(sections);
	}
	return ret;
}

#if 0
int r_bin_get_libs()
{

}
#endif
