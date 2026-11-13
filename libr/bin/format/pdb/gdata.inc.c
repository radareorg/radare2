#include "types.h"
#include "stream_file.h"
#include "tpi.h"

static int parse_global(const ut8 *data, ut32 data_size, SGlobal *global) {
	const ut32 fixed_size = 10;
	if (!can_read (0, fixed_size, data_size)) {
		return 0;
	}
	global->symtype = r_read_le32 (data);
	global->offset = r_read_le32 (data + 4);
	global->segment = r_read_le16 (data + 8);
	ut32 read_bytes = fixed_size;
	if (global->leaf_type == 0x110E) {
		if (!parse_sctring (&global->name, (ut8 *) (data + fixed_size), &read_bytes, data_size)) {
			return 0;
		}
	} else {
		if (!can_read (read_bytes, 1, data_size)) {
			return 0;
		}
		// the name is length prefixed and may not be NUL terminated
		const ut32 size = R_MIN (data[read_bytes], data_size - read_bytes - 1);
		read_bytes++;
		init_scstring (&global->name, size, (char *) (data + read_bytes));
		read_bytes += size;
	}
	return read_bytes;
}

static void free_global(void *ptr) {
	SGlobal *global = (SGlobal *)ptr;
	free (global->name.name);
	free (global);
}

static void parse_gdata_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	SGDATAStream *data_stream = (SGDATAStream *)stream;
	data_stream->globals_list = r_list_newf (free_global);
	ut16 len = 0;
	while (stream_file->pos < stream_file->end) {
		if (stream_file->end - stream_file->pos < 2) {
			stream_file->error = READ_PAGE_FAIL;
			return;
		}
		len = stream_file_read_le16 (stream_file);
		if (len == 0) {
			break;
		}
		if (len < 2 || len > stream_file->end - stream_file->pos) {
			stream_file->error = READ_PAGE_FAIL;
			return;
		}
		ut8 *data = malloc (len);
		if (!data) {
			return;
		}
		stream_file_read (stream_file, len, (char *)data);
		if (stream_file->error) {
			free (data);
			return;
		}

		ut16 leaf_type = r_read_le16 (data);
		if ((leaf_type == 0x110E) || (leaf_type == 0x1009)) {
			SGlobal *global = R_NEW0 (SGlobal);
			global->leaf_type = leaf_type;
			if (parse_global (data + 2, len - 2, global)) {
				r_list_append (data_stream->globals_list, global);
			} else {
				free_global (global);
			}
		}
		free (data);
	}
}

static void free_gdata_stream(STpiStream *ss, void *stream) {
	SGDATAStream *data_stream = (SGDATAStream *)stream;
	r_list_free (data_stream->globals_list);
}

static void free_module_proc(void *ptr) {
	SModuleProc *proc = (SModuleProc *)ptr;
	free (proc->name);
	free (proc);
}

static void parse_module_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	SModuleStream *module = (SModuleStream *)stream;
	module->procs = r_list_newf (free_module_proc);
	const ut32 size = module->sym_size;
	if (!module->procs || size < 4 || size > stream_file->end - stream_file->pos) {
		return;
	}
	ut8 *data = malloc (size);
	if (!data) {
		return;
	}
	stream_file_read (stream_file, size, (char *)data);
	if (stream_file->error) {
		// a broken module must not discard the rest of the PDB
		stream_file->error = 0;
		free (data);
		return;
	}
	// skip the CV_SIGNATURE_C13 signature
	ut32 i = 4;
	while (i + 4 <= size) {
		const ut16 len = r_read_le16 (data + i);
		if (len < 2 || len > size - i - 2) {
			break;
		}
		const ut8 *rec = data + i + 2;
		const ut16 kind = r_read_le16 (rec);
		// parent, end, next, length, debug start, debug end, type, offset, segment, flags, name
		const ut32 fixed_size = 2 + 35;
		const bool is_proc = kind == PDB_S_LPROC32 || kind == PDB_S_GPROC32
			|| kind == PDB_S_LPROC32_ID || kind == PDB_S_GPROC32_ID;
		if (is_proc && len > fixed_size) {
			SModuleProc *proc = R_NEW0 (SModuleProc);
			if (!proc) {
				break;
			}
			proc->size = r_read_le32 (rec + 2 + 12);
			proc->offset = r_read_le32 (rec + 2 + 28);
			proc->segment = r_read_le16 (rec + 2 + 32);
			proc->name = r_str_ndup ((const char *)rec + fixed_size, len - fixed_size);
			if (!proc->name) {
				free (proc);
				break;
			}
			r_list_append (module->procs, proc);
		}
		i += 2 + len;
	}
	free (data);
}

static void free_module_stream(STpiStream *ss, void *stream) {
	SModuleStream *module = (SModuleStream *)stream;
	r_list_free (module->procs);
}
