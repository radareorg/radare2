/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_BININFO_H_
#define _INCLUDE_R_BININFO_H_

#include <r_types.h>
#include <r_util.h>
#include <list.h>

#define R_BININFO_DBG_STRIPPED(x) x & 0x01
#define R_BININFO_DBG_STATIC(x)   x & 0x02
#define R_BININFO_DBG_LINENUMS(x) x & 0x04
#define R_BININFO_DBG_SYMS(x)     x & 0x08
#define R_BININFO_DBG_RELOCS(x)   x & 0x10

#define R_BININFO_SIZEOF_NAMES 256

/* types */
struct r_bininfo_t {
	const char *file;
	int fd;
	int rw;
	void *bin_obj;
	char *path;
	void *user;
	struct r_bininfo_handle_t *cur;
	struct list_head bins;
};

struct r_bininfo_handle_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	char *(*get_path)(struct r_bininfo_t *user);
	int (*get_line)(struct r_bininfo_t *user, u64 addr, char *file, int len, int *line);
	char *(*get_function_name)(struct r_bininfo_t *bi, u64 addr, char *file, int len);
	int (*open)(struct r_bininfo_t *bin);
	int (*close)(struct r_bininfo_t *bin);
	struct list_head list;
};


/* bininfo.c */
struct r_bininfo_t *r_bininfo_new();
void r_bininfo_free(struct r_bininfo_t *bin);
int r_bininfo_init(struct r_bininfo_t *bin);
void r_bininfo_set_user_ptr(struct r_bininfo_t *bin, void *user);
int r_bininfo_add(struct r_bininfo_t *bin, struct r_bininfo_handle_t *foo);
int r_bininfo_list(struct r_bininfo_t *bin);
int r_bininfo_open(struct r_bininfo_t *bin, const char *file, int rw, char *plugin_name);
int r_bininfo_close(struct r_bininfo_t *bin);
int r_bininfo_get_line(struct r_bininfo_t *bin, u64 addr, char *file, int len, int *line);
char *r_bininfo_get_source_path(struct r_bininfo_t *bin);
int r_bininfo_set_source_path(struct r_bininfo_t *bi, char *path);

/* TODO : move this to r_util!! */
char *r_bininfo_get_file_line(struct r_bininfo_t *bin, const char *file, int line);

/* plugin pointers */
extern struct r_bininfo_handle_t r_bininfo_plugin_elf;
extern struct r_bininfo_handle_t r_bininfo_plugin_elf64;
extern struct r_bininfo_handle_t r_bininfo_plugin_pe;
extern struct r_bininfo_handle_t r_bininfo_plugin_pe64;
extern struct r_bininfo_handle_t r_bininfo_plugin_java;
extern struct r_bininfo_handle_t r_bininfo_plugin_addr2line;

#endif
