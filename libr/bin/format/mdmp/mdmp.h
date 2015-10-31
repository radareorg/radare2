#ifndef MDMP_H
#define MDMP_H

#include <r_bin.h>
#include <r_types.h>

#if 0
#include "windows/types.h"
#include "windows/exception.h"
#include "windows/resources.h"
#include "windows/version_info.h"
#include "windows/time.h"
#include "windows/timezone.h"
#include "windows/processor.h"
#include "windows/products.h"
#endif
#include "windefs.h"

#include "mdmp_specs.h"

struct r_bin_mdmp_obj {
	PMINIDUMP_HEADER hdr;
	RList * /* PMINIDUMP_DIRECTORY             */ streams;
	RList * /* PMINIDUMP_THREAD                */ threads;
	RList * /* PMINIDUMP_THREAD_INFO           */ thread_info;
	RList * /* PMINIDUMP_THREAD_EX_LIST        */ threads_ex;
	RList * /* MINIDUMP_MODULE                 */ modules;
	RList * /* PMINIDUMP_UNLOADED_MODULE_LIST  */ unloaded_modules;
	RList * /* PMINIDUMP_MEMORY_LIST           */ memory;
	RList * /* PMINIDUMP_MEMORY64_LIST         */ memory64;
	RList * /* PMINIDUMP_MEMORY_INFO_LIST      */ memory_info;
	RList * /* PMINIDUMP_EXCEPTION_INFORMATION */ exceptions;
	PMINIDUMP_SYSTEM_INFO                         system_info;
	RList * /* Null-terminated ANSI String     */ comments_a;
	RList * /* Null-terminated Wide String     */ comments_w;
	RList * /* PMINIDUMP_HANDLE_DATA_STREAM    */ handle_streams;
	RList * /* PMINIDUMP_FUNCTION_TABLE_STREAM */ function_tables;
	RList * /* PMINIDUMP_MISC_INFO_N           */ misc_info;
	RList * /* PMINIDUMP_HANDLE_OPERATION_LIST */ handle_operations;
	RList * /* PMINIDUMP_TOKEN_INFO_LIST       */ token_info;
	RList * /*                                 */ javascipt_stream;

	const char *file;
	struct r_buf_t *b;
	Sdb *kv;
};

struct r_bin_mdmp_obj *r_bin_mdmp_new_buf(struct r_buf_t *buf);
void r_bin_mdmp_free(struct r_bin_mdmp_obj *obj);
bool r_bin_mdmp_create_lists(struct r_bin_mdmp_obj *obj);
void r_bin_mdmp_destroy_lists(struct r_bin_mdmp_obj *obj);
int r_bin_mdmp_init(struct r_bin_mdmp_obj *obj);
int r_bin_mdmp_init_streams(struct r_bin_mdmp_obj *obj);
int r_bin_mdmp_init_directory(struct r_bin_mdmp_obj *obj, PMINIDUMP_DIRECTORY dir);
PMINIDUMP_STRING r_bin_mdmp_locate_string(struct r_bin_mdmp_obj *obj, RVA Rva);

#endif /* MDMP_H */
