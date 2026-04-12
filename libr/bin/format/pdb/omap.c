/* radare - LGPL - Copyright 2014-2025 - iniside, pancake */

#include "types.h"
#include "omap.h"
#include "stream_file.h"

static int parse_omap_entry(char *data, int data_size, int *read_bytes, SOmapEntry *omap_entry) {
	int curr_read_bytes = *read_bytes;
	if (data_size - *read_bytes < (int)sizeof (SOmapEntry)) {
		return 0;
	}
	memcpy (omap_entry, data, sizeof (SOmapEntry));
	*read_bytes += sizeof (SOmapEntry);
	return (*read_bytes - curr_read_bytes);
}

void parse_omap_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file) {
	int data_size = stream_file_get_size (stream_file);
	if (data_size < 1) {
		return;
	}
	char *data = (char *)malloc (data_size);
	if (!data) {
		return;
	}
	stream_file_get_data (stream_file, data);

	SOmapStream *omap_stream = (SOmapStream *)stream;
	omap_stream->froms = NULL;
	omap_stream->omap_entries = r_list_newf (free);
	char *ptmp = data;
	int read_bytes = 0;
	while (read_bytes < data_size) {
		SOmapEntry *omap_entry = malloc (sizeof (SOmapEntry));
		if (!omap_entry) {
			break;
		}
		int curr_read_bytes = parse_omap_entry (ptmp, data_size, &read_bytes, omap_entry);
		if (!curr_read_bytes) {
			free (omap_entry);
			break;
		}
		ptmp += curr_read_bytes;
		r_list_append (omap_stream->omap_entries, omap_entry);
	}
	free (data);
}

void free_omap_stream(STpiStream *ss, void *stream) {
	SOmapStream *omap_stream = (SOmapStream *)stream;
	r_list_free (omap_stream->omap_entries);
}

// inclusive lower-bound binary search
static int binary_search(unsigned int *A, int key, int imin, int imax) {
	while (imin < imax) {
		int imid = (imin + imax) / 2;
		if (A[imid] < key) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}
	if ((imax == imin) && (A[imin] == (unsigned int)key)) {
		return imin;
	}
	return -1;
}

int omap_remap(void *stream, int address) {
	SOmapStream *omap_stream = (SOmapStream *)stream;
	if (!omap_stream) {
		return address;
	}

	int len = r_list_length (omap_stream->omap_entries);
	if (len < 1) {
		return -1;
	}

	if (!omap_stream->froms) {
		if (len > SIZE_MAX / sizeof (unsigned int)) {
			return -1;
		}
		omap_stream->froms = malloc (len * sizeof (unsigned int));
		if (!omap_stream->froms) {
			return -1;
		}
		int i = 0;
		SOmapEntry *omap_entry;
		RListIter *it = r_list_iterator (omap_stream->omap_entries);
		while (r_list_iter_next (it)) {
			omap_entry = (SOmapEntry *)r_list_iter_get (it);
			omap_stream->froms[i] = omap_entry->from;
			i++;
		}
	}

	int pos = binary_search (omap_stream->froms, address, 0, len - 1);
	if (pos == -1) {
		return -1;
	}
	if (omap_stream->froms[pos] != (unsigned int)address) {
		pos -= 1;
	}
	SOmapEntry *omap_entry = (SOmapEntry *)r_list_get_n (omap_stream->omap_entries, pos);
	if (!omap_entry) {
		return -1;
	}
	if (omap_entry->to == 0) {
		return 0;
	}
	return omap_entry->to + (address - omap_entry->from);
}
