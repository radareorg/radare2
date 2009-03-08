/* radare - LGPL - Copyright 2008 nibble<.ds@gmail.com> */

#ifndef _INCLUDE_R_BIN_H_
#define _INCLUDE_R_BIN_H_

#include <r_types.h>
#include <list.h>

#define R_BIN_SCN_EXECUTABLE(x) x & 0x1
#define R_BIN_SCN_WRITABLE(x)   x & 0x2
#define R_BIN_SCN_READABLE(x)   x & 0x4
#define R_BIN_SCN_SHAREABLE(x)  x & 0x8

#define R_BIN_DBG_STRIPPED(x) x & 0x01
#define R_BIN_DBG_STATIC(x)   x & 0x02
#define R_BIN_DBG_LINENUMS(x) x & 0x04
#define R_BIN_DBG_SYMS(x)     x & 0x08
#define R_BIN_DBG_RELOCS(x)   x & 0x10

#define R_BIN_SIZEOF_NAMES 64

enum {
	R_BIN_FMT_ELF32,
	R_BIN_FMT_ELF64,
	R_BIN_FMT_PE
};

/* types */
struct r_bin_t {
	const char *file;
	int fd;
	int rw;
	void *bin_obj;
	void *user;
	struct r_bin_handle_t *cur;
	struct list_head bins;
};

struct r_bin_handle_t {
	char *name;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
	int (*open)(struct r_bin_t *bin);
	int (*close)(struct r_bin_t *bin);
	u64 (*baddr)(struct r_bin_t *bin);
	struct r_bin_entry_t* (*entry)(struct r_bin_t *bin);
	struct r_bin_section_t* (*sections)(struct r_bin_t *bin);
	struct r_bin_symbol_t* (*symbols)(struct r_bin_t *bin);
	struct r_bin_import_t* (*imports)(struct r_bin_t *bin);
	struct r_bin_info_t* (*info)(struct r_bin_t *bin);
	u64 (*resize_section)(struct r_bin_t *bin, char *name, u64 size);
	struct list_head list;
};

struct r_bin_entry_t {
	u64 rva;
	u64 offset;
};

struct r_bin_section_t {
	char name[R_BIN_SIZEOF_NAMES];
	u64 size;
	u64 vsize;
	u64 rva;
	u64 offset;
	u64 characteristics;
	int last;
};

struct r_bin_symbol_t {
	char name[R_BIN_SIZEOF_NAMES];
	char forwarder[R_BIN_SIZEOF_NAMES];
	char bind[R_BIN_SIZEOF_NAMES];
	char type[R_BIN_SIZEOF_NAMES];
	u64 rva;
	u64 offset;
	u64 size;
	u64 ordinal;
	int last;
};

struct r_bin_import_t {
	char name[R_BIN_SIZEOF_NAMES];
	char bind[R_BIN_SIZEOF_NAMES];
	char type[R_BIN_SIZEOF_NAMES];
	u64 rva;
	u64 offset;
	u64 ordinal;
	u64 hint;
	int last;
};

struct r_bin_info_t {
	char type[R_BIN_SIZEOF_NAMES];
	char class[R_BIN_SIZEOF_NAMES];
	char rclass[R_BIN_SIZEOF_NAMES];
	char arch[R_BIN_SIZEOF_NAMES];
	char machine[R_BIN_SIZEOF_NAMES];
	char os[R_BIN_SIZEOF_NAMES];
	char subsystem[R_BIN_SIZEOF_NAMES];
	int big_endian;
	u64 dbg_info;
};

/* bin.c */
struct r_bin_t *r_bin_new(char *file, int rw);
void r_bin_free(struct r_bin_t *bin);
int r_bin_init(struct r_bin_t *bin);
void r_bin_set_user_ptr(struct r_bin_t *bin, void *user);
int r_bin_add(struct r_bin_t *bin, struct r_bin_handle_t *foo);
int r_bin_list(struct r_bin_t *bin);
int r_bin_set(struct r_bin_t *bin, const char *name);
int r_bin_autoset(struct r_bin_t *bin);
int r_bin_set_file(struct r_bin_t *bin, const char *file, int rw);
int r_bin_open(struct r_bin_t *bin);
int r_bin_close(struct r_bin_t *bin);
u64 r_bin_get_baddr(struct r_bin_t *bin);
struct r_bin_entry_t* r_bin_get_entry(struct r_bin_t *bin);
struct r_bin_section_t* r_bin_get_sections(struct r_bin_t *bin);
struct r_bin_symbol_t* r_bin_get_symbols(struct r_bin_t *bin);
struct r_bin_import_t* r_bin_get_imports(struct r_bin_t *bin);
struct r_bin_info_t* r_bin_get_info(struct r_bin_t *bin);
u64 r_bin_resize_section(struct r_bin_t *bin, char *name, u64 size);
u64 r_bin_get_section_offset(struct r_bin_t *bin, char *name);
u64 r_bin_get_section_rva(struct r_bin_t *bin, char *name);
u64 r_bin_get_section_size(struct r_bin_t *bin, char *name);

#endif
