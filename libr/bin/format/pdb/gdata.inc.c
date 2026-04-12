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
		parse_sctring (&global->name, (ut8 *) (data + fixed_size), &read_bytes, data_size);
	} else {
		if (!can_read (read_bytes, 1, data_size)) {
			return 0;
		}
		global->name.size = data[read_bytes];
		read_bytes++;
		init_scstring (&global->name, global->name.size, (char *) (data + read_bytes));
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
	while (1) {
		stream_file_read (stream_file, 2, (char *)&len);
		if (len == 0) {
			break;
		}
		ut8 *data = malloc (len);
		if (!data) {
			return;
		}
		stream_file_read (stream_file, len, (char *)data);

		ut16 leaf_type = r_read_le16 (data);
		if ((leaf_type == 0x110E) || (leaf_type == 0x1009)) {
			SGlobal *global = R_NEW0 (SGlobal);
			global->leaf_type = leaf_type;
			parse_global (data + 2, len - 2, global);
			r_list_append (data_stream->globals_list, global);
		}
		free (data);
	}
}

static void free_gdata_stream(STpiStream *ss, void *stream) {
	SGDATAStream *data_stream = (SGDATAStream *)stream;
	r_list_free (data_stream->globals_list);
}
