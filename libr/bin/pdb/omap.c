#include "omap.h"

#include "types.h"
#include "stream_file.h"

///////////////////////////////////////////////////////////////////////////////
static int parse_omap_entry(char *data, int data_size, int *read_bytes, SOmapEntry *omap_entry)
{
	int curr_read_bytes = *read_bytes;

	memcpy(omap_entry, data, sizeof(SOmapEntry));
	*read_bytes += sizeof(SOmapEntry);

	return (*read_bytes - curr_read_bytes);
}

///////////////////////////////////////////////////////////////////////////////
void parse_omap_stream(void *stream, R_STREAM_FILE *stream_file)
{
	int data_size;
	char *data = 0, *ptmp = 0;
	int curr_read_bytes = 0, read_bytes = 0;
	SOmapEntry *omap_entry = 0;
	SOmapStream *omap_stream = 0;

	stream_file_get_size(stream_file, &data_size);
	data = (char *) malloc(data_size);
	stream_file_get_data(stream_file, data);

	omap_stream = (SOmapStream *) stream;
	omap_stream->froms = 0;
	omap_stream->omap_entries = r_list_new();
	curr_read_bytes = 0;
	ptmp = data;
	while (read_bytes < data_size) {
		omap_entry = (SOmapEntry *) malloc(sizeof(SOmapEntry));
		curr_read_bytes = parse_omap_entry(ptmp, data_size, &read_bytes, omap_entry);
		ptmp += curr_read_bytes;

		if (!curr_read_bytes) {
			free(omap_entry);
			break;
		}

		r_list_append(omap_stream->omap_entries, omap_entry);
	}

	free(data);
}

///////////////////////////////////////////////////////////////////////////////
void free_omap_stream(void *stream)
{
	SOmapStream *omap_stream = (SOmapStream *) stream;
	RListIter *it = 0;
	SOmapEntry *omap_entry = 0;

	it = r_list_iterator(omap_stream->omap_entries);
	while (r_list_iter_next(it)) {
		omap_entry = (SOmapEntry *) r_list_iter_get(it);
		free(omap_entry);
	}
	r_list_free(omap_stream->omap_entries);
}

// inclusive indices
//   0 <= imin when using truncate toward zero divide
//     imid = (imin+imax)/2;
//   imin unrestricted when using truncate toward minus infinity divide
//     imid = (imin+imax)>>1; or
//     imid = (int)floor((imin+imax)/2.0);
static int binary_search(unsigned int *A, int key, int imin, int imax)
{
	int imid;

	// continually narrow search until just one element remains
	while (imin < imax)
	{
		imid = (imin + imax) / 2;

		if (A[imid] < key)
			imin = imid + 1;
		else
			imax = imid;
	}
	// At exit of while:
	//   if A[] is empty, then imax < imin
	//   otherwise imax == imin

	// deferred test for equality
	if ((imax == imin) && (A[imin] == key))
		return imin;
	else
		return -1;
}

///////////////////////////////////////////////////////////////////////////////
int omap_remap(void *stream, int address)
{
	SOmapStream *omap_stream = (SOmapStream *) stream;
	SOmapEntry *omap_entry = 0;
	RListIter *it = 0;
	int i = 0;
	int pos = 0;
	int len = 0;

	if (!omap_stream) {
		return address;
	}

	len = r_list_length(omap_stream->omap_entries);

	if (omap_stream->froms == 0) {
		omap_stream->froms = (unsigned int *) malloc(4 * len);
		it = r_list_iterator(omap_stream->omap_entries);
		while (r_list_iter_next(it)) {
			omap_entry = (SOmapEntry *) r_list_iter_get(it);
			omap_stream->froms[i] = omap_entry->from;
			i++;
		}
	}

	// mb (len -1) ???
	pos = binary_search(omap_stream->froms, address, 0, (len));

	if (omap_stream->froms[pos] != address) {
		pos -= 1;
	}

	omap_entry = (SOmapEntry *) r_list_get_n(omap_stream->omap_entries, pos);
	if (!omap_entry) {
		return -1;
	}
	if (omap_entry->to == 0) {
		return omap_entry->to;
	} else {
		return omap_entry->to + (address - omap_entry->from);
	}
}
