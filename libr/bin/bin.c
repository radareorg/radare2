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
	u8 *buf = NULL;
	u64 len, max_str = 0;
	int i, matches = 0, ctr = 0;
	char str[R_BIN_SIZEOF_NAMES];

	len = lseek(bin->fd, 0, SEEK_END);
	max_str = (u64)(len/min);

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
				ret[ctr].offset = i-matches;
				ret[ctr].size = matches;
				memcpy(ret[ctr].string, str, R_BIN_SIZEOF_NAMES);
				ret[ctr].string[R_BIN_SIZEOF_NAMES-1] = '\0';
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

struct r_bin_t *r_bin_new(char *file, int rw)
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

int r_bin_set(struct r_bin_t *bin, const char *name)
{
	struct list_head *pos;
	list_for_each_prev(pos, &bin->bins) {
		struct r_bin_handle_t *h = list_entry(pos, struct r_bin_handle_t, list);
		if (!strcmp(h->name, name)) {
			bin->cur = h;
			return R_TRUE;
		}
	}
	return R_FALSE;
}

/*XXX*/
int r_bin_autoset(struct r_bin_t *bin)
{
	unsigned char buf[1024];

	if ((bin->fd = open(bin->file, 0)) == -1) {
		return -1;
	}

	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, 1024);

	close(bin->fd);

	if (!memcmp(buf, "\x7F\x45\x4c\x46", 4)) {
		if (buf[4] == 2)  /* buf[EI_CLASS] == ELFCLASS64 */
			return r_bin_set(bin, "bin_elf64");
		else return r_bin_set(bin, "bin_elf");
	} else if (!memcmp(buf, "\x4d\x5a", 2) &&
			!memcmp(buf+(buf[0x3c]|(buf[0x3d]<<8)), "\x50\x45", 2)) {
		if (!memcmp(buf+(buf[0x3c]|buf[0x3d]<<8)+0x18, "\x0b\x02", 2))
			return r_bin_set(bin, "bin_pe64");
		else return r_bin_set(bin, "bin_pe");
	} else if (!memcmp(buf, "\xca\xfe\xba\xbe", 4))
		return r_bin_set(bin, "bin_java");

	return R_FALSE;
}

int r_bin_set_file(struct r_bin_t *bin, const char *file, int rw)
{
	bin->file = file;
	bin->rw = rw;

	return R_TRUE;
}

int r_bin_open(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->open)
		return bin->cur->open(bin);
	
	return R_FALSE;
}

int r_bin_close(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->close)
		return bin->cur->close(bin);
	
	return R_FALSE;
}

u64 r_bin_get_baddr(struct r_bin_t *bin)
{
	if (bin->cur && bin->cur->baddr)
		return bin->cur->baddr(bin);
	
	return R_FALSE;
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

u64 r_bin_resize_section(struct r_bin_t *bin, char *name, u64 size)
{
	if (bin->cur && bin->cur->resize_section)
		return bin->cur->resize_section(bin, name, size);

	return 0;
}

u64 r_bin_get_section_offset(struct r_bin_t *bin, char *name)
{
	struct r_bin_section_t *sections, *sectionsp;
	u64 ret = -1;

	if (!(sections = r_bin_get_sections(bin)))
		return R_FALSE;

	sectionsp = sections;
	while (!sectionsp->last) {
		if (!strcmp(sectionsp->name, name)) {
			ret = sectionsp->offset;
			break;
		}

		sectionsp++;
	}

	free(sections);

	return ret;
}

u64 r_bin_get_section_rva(struct r_bin_t *bin, char *name)
{
	struct r_bin_section_t *sections, *sectionsp;
	u64 ret = -1;

	if (!(sections = r_bin_get_sections(bin)))
		return R_FALSE;

	sectionsp = sections;
	while (!sectionsp->last) {
		if (!strcmp(sectionsp->name, name)) {
			ret = sectionsp->rva;
			break;
		}

		sectionsp++;
	}

	free(sections);

	return ret;
}

u64 r_bin_get_section_size(struct r_bin_t *bin, char *name)
{
	struct r_bin_section_t *sections, *sectionsp;
	u64 ret = -1;

	if (!(sections = r_bin_get_sections(bin)))
		return R_FALSE;

	sectionsp = sections;
	while (!sectionsp->last) {
		if (!strcmp(sectionsp->name, name)) {
			ret = sectionsp->size;
			break;
		}
		sectionsp++;
	}

	free(sections);

	return ret;
}

#if 0
int r_bin_get_libs()
{

}

int r_bin_get_strings()
{

}
#endif
