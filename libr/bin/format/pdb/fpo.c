/* radare - LGPL - Copyright 2014-2025 - inisider, pancake */

#include "types.h"
#include "fpo.h"
#include "stream_file.h"

static int parse_fpo_data(const ut8 *data, ut32 data_size, ut32 pos, SFPO_DATA *fpo_data) {
	const ut32 size = 16;
	if (!can_read (pos, size, data_size)) {
		return 0;
	}
	fpo_data->ul_off_start = r_read_le32 (data);
	fpo_data->cb_proc_size = r_read_le32 (data + 4);
	fpo_data->cdw_locals = r_read_le32 (data + 8);
	fpo_data->cdw_params = r_read_le16 (data + 12);
	fpo_data->bit_values.bit_values = r_read_be16 (data + 14);
	return size;
}

static int parse_fpo_data_v2(const ut8 *data, ut32 data_size, ut32 pos, SFPO_DATA_V2 *fpo_data) {
	const ut32 size = sizeof (SFPO_DATA_V2);
	if (!can_read (pos, size, data_size)) {
		return 0;
	}
	memcpy (fpo_data, data, size);
	return size;
}

void parse_fpo_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	int data_size = stream_file_get_size (stream_file);
	if (data_size < 1) {
		return;
	}
	ut8 *data = malloc (data_size);
	if (!data) {
		return;
	}
	stream_file_get_data (stream_file, (char *)data);

	SFPOStream *fpo_stream = (SFPOStream *)stream;
	fpo_stream->fpo_data_list = r_list_new ();
	ut32 pos = 0;
	while (pos < (ut32)data_size) {
		SFPO_DATA *fpo_data = R_NEW0 (SFPO_DATA);
		const int sz = parse_fpo_data (data + pos, data_size, pos, fpo_data);
		if (!sz) {
			free (fpo_data);
			break;
		}
		r_list_append (fpo_stream->fpo_data_list, fpo_data);
		pos += sz;
	}
	free (data);
}

void free_fpo_stream(STpiStream *ss, void *stream) {
	SFPOStream *fpo_stream = (SFPOStream *)stream;
	RListIter *it = 0;
	SFPO_DATA *fpo_data = 0;

	it = r_list_iterator (fpo_stream->fpo_data_list);
	while (r_list_iter_next (it)) {
		fpo_data = (SFPO_DATA *)r_list_iter_get (it);
		free (fpo_data);
	}
	r_list_free (fpo_stream->fpo_data_list);
}

void free_fpo_new_stream(STpiStream *ss, void *stream) {
	SFPONewStream *fpo_stream = (SFPONewStream *)stream;
	RListIter *it = 0;
	SFPO_DATA_V2 *fpo_data = 0;

	it = r_list_iterator (fpo_stream->fpo_data_list);
	while (r_list_iter_next (it)) {
		fpo_data = (SFPO_DATA_V2 *)r_list_iter_get (it);
		free (fpo_data);
	}
	r_list_free (fpo_stream->fpo_data_list);
}

void parse_fpo_new_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	int data_size = stream_file_get_size (stream_file);
	if (data_size < 1) {
		return;
	}
	ut8 *data = malloc (data_size);
	if (!data) {
		return;
	}
	stream_file_get_data (stream_file, (char *)data);

	SFPONewStream *fpo_stream = (SFPONewStream *)stream;
	fpo_stream->fpo_data_list = r_list_new ();
	ut32 pos = 0;
	while (pos < (ut32)data_size) {
		SFPO_DATA_V2 *fpo_data = malloc (sizeof (SFPO_DATA_V2));
		if (!fpo_data) {
			break;
		}
		const int sz = parse_fpo_data_v2 (data + pos, data_size, pos, fpo_data);
		if (!sz) {
			free (fpo_data);
			break;
		}
		r_list_append (fpo_stream->fpo_data_list, fpo_data);
		pos += sz;
	}
	free (data);
}
