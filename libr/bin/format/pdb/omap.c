/* radare - LGPL - Copyright 2014-2025 - iniside, pancake */

#include "types.h"
#include "omap.h"
#include "stream_file.h"

void parse_omap_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	SOmapStream *omap_stream = (SOmapStream *)stream;
	omap_stream->entries = NULL;
	omap_stream->count = 0;
	int data_size = stream_file_get_size (stream_file);
	if (data_size < 1) {
		return;
	}
	ut8 *data = malloc (data_size);
	if (!data) {
		return;
	}
	if (!stream_file_get_data (stream_file, (char *)data)) {
		free (data);
		return;
	}
	const int count = data_size / sizeof (SOmapEntry);
	omap_stream->entries = R_NEWS (SOmapEntry, R_MAX (count, 1));
	if (omap_stream->entries) {
		int i;
		for (i = 0; i < count; i++) {
			omap_stream->entries[i].from = r_read_le32 (data + i * sizeof (SOmapEntry));
			omap_stream->entries[i].to = r_read_le32 (data + i * sizeof (SOmapEntry) + 4);
		}
		omap_stream->count = count;
	}
	free (data);
}

void free_omap_stream(STpiStream *ss, void *stream) {
	SOmapStream *omap_stream = (SOmapStream *)stream;
	free (omap_stream->entries);
}

// the entry whose from is address, entries are sorted by from
int omap_remap(void *stream, int address) {
	SOmapStream *omap_stream = (SOmapStream *)stream;
	if (!omap_stream) {
		return address;
	}
	int lo = 0;
	int hi = omap_stream->count;
	while (lo < hi) {
		const int mid = lo + (hi - lo) / 2;
		if (omap_stream->entries[mid].from < (ut32)address) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	if (lo >= omap_stream->count || omap_stream->entries[lo].from != (ut32)address) {
		return -1;
	}
	const SOmapEntry *omap_entry = &omap_stream->entries[lo];
	if (omap_entry->to == 0) {
		return 0;
	}
	return omap_entry->to + (address - omap_entry->from);
}
