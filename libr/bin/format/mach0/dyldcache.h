/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include "mach0_specs.h"

#ifndef _INCLUDE_R_BIN_DYLDCACHE_H_
#define _INCLUDE_R_BIN_DYLDCACHE_H_

struct r_bin_dyldcache_obj_t {
	const char *file;
	int size;
	int nlibs;
	struct cache_header hdr;
	struct r_buf_t* b;
};

struct r_bin_dyldcache_lib_t {
	char path[1024];
	int size;
	struct r_buf_t *b; 
	int last;
};

struct r_bin_dyldcache_lib_t *r_bin_dyldcache_extract(struct r_bin_dyldcache_obj_t* bin, int idx, int *nlib);
void *r_bin_dyldcache_free(struct r_bin_dyldcache_obj_t* bin);
struct r_bin_dyldcache_obj_t* r_bin_dyldcache_new(const char* file);

#endif
