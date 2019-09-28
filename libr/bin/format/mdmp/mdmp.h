/* radare2 - LGPL - Copyright 2016 - Davis, Alex Kornitzer */

#ifndef MDMP_H
#define MDMP_H

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "mdmp_specs.h"
#include "mdmp_pe.h"
#include "mdmp_pe64.h"

struct r_bin_mdmp_obj {
	struct minidump_header *hdr;

	/* Encountered streams */
	struct minidump_streams {
		ut8 *comments_a;
		ut8 *comments_w;

		struct minidump_exception_stream *exception;
		struct minidump_function_table_stream *function_table;
		struct minidump_handle_data_stream *handle_data;
		struct minidump_system_info *system_info;

		union {
			struct minidump_misc_info *misc_info_1;
			struct minidump_misc_info_2 *misc_info_2;
		} misc_info;

		/* Lists */
		RList *ex_threads;
		RList *memories;
		RList *memory_infos;
		RList *modules;
		RList *operations;
		RList *thread_infos;
		RList *threads;
		RList *token_infos;
		RList *unloaded_modules;
		struct {
			rva64_t base_rva;
			RList *memories;
		} memories64;
	} streams;

	/* Binary memory objects */
	RList *pe32_bins;
	RList *pe64_bins;

	RBuffer *b;
	size_t size;
	ut8 endian;
	Sdb *kv;
};

struct r_bin_mdmp_obj *r_bin_mdmp_new_buf(RBuffer *buf);
void r_bin_mdmp_free(struct r_bin_mdmp_obj *obj);
ut64 r_bin_mdmp_get_paddr(struct r_bin_mdmp_obj *obj, ut64 vaddr);
ut32 r_bin_mdmp_get_perm(struct r_bin_mdmp_obj *obj, ut64 vaddr);
struct minidump_memory_info *r_bin_mdmp_get_mem_info(struct r_bin_mdmp_obj *obj, ut64 vaddr);

#endif /* MDMP_H */
