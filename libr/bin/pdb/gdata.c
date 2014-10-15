#include "gdata.h"

#include "stream_file.h"
#include "tpi.h"

///////////////////////////////////////////////////////////////////////////////
static int parse_global(char *data, int data_size, SGlobal *global) {
	unsigned int read_bytes = 2;

	READ(read_bytes, 4, data_size, global->symtype, data, unsigned int);
	READ(read_bytes, 4, data_size, global->offset, data, unsigned int);
	READ(read_bytes, 2, data_size, global->segment, data, unsigned short);
	if (global->leaf_type == 0x110E) {
		parse_sctring(&global->name, (unsigned char *)data, &read_bytes, data_size);
	} else {
		READ(read_bytes, 1, data_size, global->name.size, data, unsigned char);
		init_scstring(&global->name, global->name.size, data);
	}

	return read_bytes;
}

///////////////////////////////////////////////////////////////////////////////
void parse_gdata_stream(void *stream, R_STREAM_FILE *stream_file) {
	unsigned short len = 0;
	unsigned short leaf_type = 0;
	char *data = 0;
	SGDATAStream *data_stream = (SGDATAStream *) stream;
	SGlobal *global = 0;

	data_stream->globals_list = r_list_new();
	while (1) {
		stream_file_read(stream_file, 2, (char *)&len);
		if (len == 0)
			break;
		data = (char *) malloc(len);
		stream_file_read(stream_file, len, data);

		leaf_type = *(unsigned short *) (data);
		if ((leaf_type == 0x110E) || (leaf_type == 0x1009)) {
			global = (SGlobal *) malloc(sizeof(SGlobal));
			global->leaf_type = leaf_type;
			parse_global(data + 2, len, global);
			r_list_append(data_stream->globals_list, global);
		}
		free(data);
	}

	// TODO: for more fast access
//	for g in self.globals:
//        if not hasattr(g, 'symtype'): continue
//        if g.symtype == 0:
//            if g.name.startswith("_"):
//                self.vars[g.name[1:]] = g
//            else:
//                self.vars[g.name] = g
//        elif g.symtype == 2:
//            self.funcs[g.name] = g
}

///////////////////////////////////////////////////////////////////////////////
void free_gdata_stream(void *stream)
{
	SGDATAStream *data_stream = (SGDATAStream *) stream;
	SGlobal *global = 0;
	RListIter *it = 0;

	it = r_list_iterator(data_stream->globals_list);
	while (r_list_iter_next(it)) {
		global = (SGlobal *) r_list_iter_get(it);
		if (global->name.name)
			free(global->name.name);
		free(global);
	}
	r_list_free(data_stream->globals_list);
}
