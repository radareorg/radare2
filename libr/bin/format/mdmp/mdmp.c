/* radare - LGPL - Copyright 2015 - Dāvis */
#include <r_util.h>

#include "mdmp.h"

struct r_bin_mdmp_obj *r_bin_mdmp_new_buf(struct r_buf_t *buf) {
	struct r_bin_mdmp_obj *obj = R_NEW0(struct r_bin_mdmp_obj);
	if (!obj) return NULL;
	obj->b = r_buf_new_with_buf (buf);
	if (!obj->b) {
		eprintf ("r_bin_mdmp_new_buf: r_buf_new_with_buf failed\n");
		r_bin_mdmp_free (obj);
		return NULL;
	}
	obj->kv = sdb_new0 ();
	if (!r_bin_mdmp_init (obj)) {
		r_bin_mdmp_free (obj);
		return NULL;
	}
	return obj;
}

void r_bin_mdmp_free(struct r_bin_mdmp_obj *obj) {
	if (!obj) return;
	r_bin_mdmp_destroy_lists(obj);
	obj->system_info = NULL;
	obj->hdr = NULL;
	if (obj->kv) {
		sdb_free (obj->kv);
		obj->kv = NULL;
	}
	if (obj->b) {
		r_buf_free (obj->b);
		obj->b = NULL;
	}
	free (obj);
}

bool r_bin_mdmp_create_lists(struct r_bin_mdmp_obj *obj) {
	if (!(obj->streams = r_list_new())) return false;
	if (!(obj->threads = r_list_new())) return false;
	if (!(obj->thread_info = r_list_new())) return false;
	if (!(obj->threads_ex = r_list_new())) return false;
	if (!(obj->modules = r_list_new())) return false;
	if (!(obj->unloaded_modules = r_list_new())) return false;
	if (!(obj->memory = r_list_new())) return false;
	if (!(obj->memory64 = r_list_new())) return false;
	if (!(obj->memory_info = r_list_new())) return false;
	if (!(obj->exceptions = r_list_new())) return false;
	if (!(obj->comments_a = r_list_new())) return false;
	if (!(obj->comments_w = r_list_new())) return false;
	if (!(obj->handle_streams = r_list_new())) return false;
	if (!(obj->function_tables = r_list_new())) return false;
	if (!(obj->misc_info = r_list_newf (free))) return false;
	if (!(obj->handle_operations = r_list_new ())) return false;
	if (!(obj->token_info = r_list_new())) return false;
	return true;
}

void r_bin_mdmp_destroy_lists(struct r_bin_mdmp_obj *obj) {
	if (obj->threads) {
		r_list_free(obj->threads);
		obj->threads = NULL;
	}

	if (obj->thread_info) {
		r_list_free(obj->thread_info);
		obj->thread_info = NULL;
	}

	if (obj->threads_ex) {
		r_list_free(obj->threads_ex);
		obj->threads_ex = NULL;
	}

	if (obj->modules) {
		r_list_free(obj->modules);
		obj->modules = NULL;
	}

	if (obj->unloaded_modules) {
		r_list_free(obj->unloaded_modules);
		obj->unloaded_modules = NULL;
	}

	if (obj->memory) {
		r_list_free(obj->memory);
		obj->memory = NULL;
	}

	if (obj->memory64) {
		r_list_free(obj->memory64);
		obj->memory64 = NULL;
	}

	if (obj->memory_info) {
		r_list_free(obj->memory_info);
		obj->memory_info = NULL;
	}

	if (obj->exceptions) {
		r_list_free(obj->exceptions);
		obj->exceptions = NULL;
	}

	if (obj->comments_a) {
		r_list_free(obj->comments_a);
		obj->comments_a = NULL;
	}

	if (obj->comments_w) {
		r_list_free(obj->comments_w);
		obj->comments_w = NULL;
	}

	if (obj->handle_streams) {
		r_list_free(obj->handle_streams);
		obj->handle_streams = NULL;
	}

	if (obj->function_tables) {
		r_list_free(obj->function_tables);
		obj->function_tables = NULL;
	}

	if (obj->misc_info) {
		r_list_free(obj->misc_info);
		obj->misc_info = NULL;
	}

	if (obj->handle_operations) {
		r_list_free(obj->handle_operations);
		obj->handle_operations = NULL;
	}

	if (obj->token_info) {
		r_list_free(obj->token_info);
		obj->token_info = NULL;
	}

	if (obj->streams) {
		r_list_free(obj->streams);
		obj->streams = NULL;
	}
}

int r_bin_mdmp_init(struct r_bin_mdmp_obj *obj) {
	if (obj->b->length < sizeof(MINIDUMP_HEADER)) {
		eprintf("Error in r_bin_mdmp_init: length too short, not enough space for MINIDUMP_HEADER\n");
		return R_FALSE;
	}

	obj->hdr = (PMINIDUMP_HEADER)obj->b->buf;

	if (obj->hdr->NumberOfStreams <= 0) {
		eprintf("Error in r_bin_mdmp_init: no streams\n");
		return R_FALSE;
	}

	if (obj->hdr->StreamDirectoryRva < sizeof(obj->hdr)) {
		eprintf("Error in r_bin_mdmp_init: invalid StreamDirectoryRva, size %d\n", obj->hdr->StreamDirectoryRva);
		return R_FALSE;
	}

	if (obj->hdr->CheckSum != 0) {
		eprintf("Warning in r_bin_mdmp_init: CheckSum present, but not validated, because validation not implemented yet\n");
	}

	sdb_num_set (obj->kv, "mdmp.hdr.TimeDateStamp", obj->hdr->TimeDateStamp, 0);
	sdb_num_set (obj->kv, "mdmp.hdr.Flags", obj->hdr->Flags, 0);

	if (!r_bin_mdmp_init_streams(obj)) {
		return R_FALSE;
	}
	return R_TRUE;
}

int r_bin_mdmp_init_streams(struct r_bin_mdmp_obj *obj) {
	size_t i, l;
	PMINIDUMP_DIRECTORY dir;

	if (obj->streams)
		return R_TRUE;

	if(!r_bin_mdmp_create_lists(obj))
		return R_FALSE;

	for (i = 0; i < obj->hdr->NumberOfStreams; i++) {
		l = obj->hdr->StreamDirectoryRva + i * sizeof(MINIDUMP_DIRECTORY);
		if (l + sizeof(MINIDUMP_DIRECTORY) > obj->b->length) {
			eprintf("Warning in r_bin_mdmp_init_streams: length too short, not enough space for all streams\n");
			break;
		}
		dir = (PMINIDUMP_DIRECTORY)(obj->b->buf + l);
		eprintf("ss %d\n", dir->StreamType);
		r_bin_mdmp_init_directory(obj, dir);
		r_list_append(obj->streams, dir);
	};

	if (!obj->system_info) {
		eprintf("Warning in r_bin_mdmp_init_streams: SystemInfoStream not found\n");
		return R_FALSE;
	}

	return R_TRUE;
}

int r_bin_mdmp_directory_check(struct r_bin_mdmp_obj *obj, PMINIDUMP_DIRECTORY dir, size_t size, char *name) {
	if (size > dir->Location.DataSize) {
		eprintf("Warning in r_bin_mdmp_directory_check: %s DataSize mismatch\n", name);
		return R_FALSE;
	};
	if (dir->Location.Rva + dir->Location.DataSize > obj->b->length) {
		eprintf("Warning in r_bin_mdmp_directory_check: length too short, not enough space for %s\n", name);
		return R_FALSE;
	}
	return R_TRUE;
}

int r_bin_mdmp_init_directory(struct r_bin_mdmp_obj *obj, PMINIDUMP_DIRECTORY dir)
{
	size_t i, j, k;
	void *p, *m;
	switch (dir->StreamType) {
	case UnusedStream:
		break;
	case ThreadListStream:
		if (r_bin_mdmp_directory_check(obj, dir, sizeof(MINIDUMP_THREAD), "ThreadListStream")) {
			r_list_append(obj->threads, obj->b->buf + dir->Location.Rva);
		};
		break;
	case ModuleListStream:
		if (r_bin_mdmp_directory_check(obj, dir, sizeof(MINIDUMP_MODULE_LIST), "ModuleListStream"))
		{
			p = obj->b->buf + dir->Location.Rva;
			j = ((PMINIDUMP_MODULE_LIST)p)->NumberOfModules;
			for (i = 0; i < j; i++) {
				p = (void *)(&((PMINIDUMP_MODULE_LIST)p)->Modules[i]);
				if (p - (void *)obj->b->buf + sizeof(MINIDUMP_MODULE) > obj->b->length) {
					eprintf("Warning in r_bin_mdmp_init_directory: length too short, not enough space for all MINIDUMP_MODULE\n");
					break;
				}
				r_list_append(obj->modules, p);
			};
		};
		break;
	case MemoryListStream:
		break;
	case ExceptionStream:
		break;
	case SystemInfoStream:
		if (obj->system_info)
		{
			eprintf("Warning in r_bin_mdmp_init_directory: another SystemInfoStream encountered, ignored\n");
			return R_FALSE;
		}
		if (r_bin_mdmp_directory_check(obj, dir, sizeof(MINIDUMP_SYSTEM_INFO), "SystemInfoStream"))
		{
			obj->system_info = (PMINIDUMP_SYSTEM_INFO)(obj->b->buf + dir->Location.Rva);
		};
		break;
	case ThreadExListStream:
		break;
	case Memory64ListStream:
		if (r_bin_mdmp_directory_check(obj, dir, sizeof(MINIDUMP_MEMORY64_LIST), "Memory64ListStream"))
		{
			p = obj->b->buf + dir->Location.Rva;
			j = ((PMINIDUMP_MEMORY64_LIST)p)->NumberOfMemoryRanges;
			for (i = 0; i < j; i++) {
				p = (void *)(&((PMINIDUMP_MEMORY64_LIST)p)->MemoryRanges[i]);
				if (p - (void *)obj->b->buf + sizeof(MINIDUMP_MEMORY_DESCRIPTOR64) > obj->b->length) {
					eprintf("Warning in r_bin_mdmp_init_directory: length too short, not enough space for all MINIDUMP_MEMORY_DESCRIPTOR64\n");
					break;
				}
				r_list_append(obj->memory64, p);
			};
		};
		break;
	case CommentStreamA:
		break;
	case CommentStreamW:
		break;
	case HandleDataStream:
		break;
	case FunctionTableStream:
		break;
	case UnloadedModuleListStream:
		break;
	case MiscInfoStream:
		if (dir->Location.Rva + dir->Location.DataSize > obj->b->length)
		{
			eprintf("Warning in r_bin_mdmp_init_directory: length too short, not enough space for MiscInfoStream\n");
			return R_FALSE;
		}
		p = obj->b->buf + dir->Location.Rva;
		i = ((PMINIDUMP_MISC_INFO)p)->SizeOfInfo;
		if (i != dir->Location.DataSize) {
			eprintf("Warning in r_bin_mdmp_init_directory: MINIDUMP_MISC_INFO DataSize size mismatch\n");
			return R_FALSE;
		}
		if(!(m = malloc(sizeof(MINIDUMP_MISC_INFO_N)))) {
			eprintf("Warning in r_bin_mdmp_init_directory: malloc failed\n");
			return R_FALSE;
		}
		memset(m, 0, sizeof(MINIDUMP_MISC_INFO_N));
		if (i <= sizeof(MINIDUMP_MISC_INFO_N)) {
			memcpy(m, p, i);
		} else {
			memcpy (m, p, sizeof(MINIDUMP_MISC_INFO_N));
			eprintf ("Warning in r_bin_mdmp_init_directory: PMINIDUMP_MISC_INFO structure bigger than expected, truncated from %d\n", (int)i);
		}
		r_list_append(obj->misc_info, m);
		break;
	case MemoryInfoListStream:
		if (r_bin_mdmp_directory_check(obj, dir, sizeof(MINIDUMP_MEMORY_INFO_LIST), "MemoryInfoListStream"))
		{
			p = obj->b->buf + dir->Location.Rva;
			if ((sizeof(MINIDUMP_MEMORY_INFO_LIST) != ((PMINIDUMP_MEMORY_INFO_LIST)p)->SizeOfHeader) || (sizeof(MINIDUMP_MEMORY_INFO) != ((PMINIDUMP_MEMORY_INFO_LIST)p)->SizeOfEntry))
			{
				eprintf("Warning in r_bin_mdmp_init_directory: MemoryInfoListStream size mismatch\n");
				return R_FALSE;
			};
			j = ((PMINIDUMP_MEMORY_INFO_LIST)p)->NumberOfEntries;
			for (i = 0; i < j; i++) {
				k = dir->Location.Rva + sizeof(MINIDUMP_MEMORY_INFO_LIST) + i * sizeof(MINIDUMP_MEMORY_INFO);
				if (k + sizeof(MINIDUMP_MEMORY_INFO) > obj->b->length) {
					eprintf("Warning in r_bin_mdmp_init_directory: length too short, not enough space for all MINIDUMP_MEMORY_INFO\n");
					break;
				}
				r_list_append(obj->memory_info, obj->b->buf + k);
			};
		};
		break;
	case ThreadInfoListStream:
		if (r_bin_mdmp_directory_check(obj, dir, sizeof(MINIDUMP_THREAD_INFO_LIST), "ThreadInfoListStream"))
		{
			p = obj->b->buf + dir->Location.Rva;
			if ((sizeof(MINIDUMP_THREAD_INFO_LIST) != ((PMINIDUMP_THREAD_INFO_LIST)p)->SizeOfHeader) || (sizeof(MINIDUMP_THREAD_INFO) != ((PMINIDUMP_THREAD_INFO_LIST)p)->SizeOfEntry))
			{
				eprintf("Warning in r_bin_mdmp_init_directory: ThreadInfoListStream size mismatch\n");
				return R_FALSE;
			};
			j = ((PMINIDUMP_THREAD_INFO_LIST)p)->NumberOfEntries;
			for (i = 0; i < j; i++) {
				k = dir->Location.Rva + sizeof(MINIDUMP_THREAD_INFO_LIST) + i * sizeof(MINIDUMP_THREAD_INFO);
				if (k + sizeof(MINIDUMP_THREAD_INFO) > obj->b->length) {
					eprintf("Warning in r_bin_mdmp_init_directory: length too short, not enough space for all MINIDUMP_THREAD_INFO\n");
					break;
				}
				r_list_append(obj->thread_info, obj->b->buf + k);
			};
		};
		break;
	case HandleOperationListStream:
		break;
	case TokenStream:
		break;
	case JavaScriptDataStream:
		break;
	default
			:
		eprintf("Warning in r_bin_mdmp_init_directory: uknown stream %d\n", dir->StreamType);
	}
	return R_TRUE;
}

PMINIDUMP_STRING r_bin_mdmp_locate_string(struct r_bin_mdmp_obj *obj, RVA Rva) {
	if (Rva < obj->b->length)
		return NULL;
	return (PMINIDUMP_STRING)(obj->b->buf + Rva);
}
