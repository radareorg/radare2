#include "fpo.h"

#include "stream_file.h"

///////////////////////////////////////////////////////////////////////////////
static int parse_fpo_data(char *data, int data_size, int *read_bytes, SFPO_DATA *fpo_data)
{
	int curr_read_bytes = *read_bytes;

	READ(*read_bytes, 4, data_size, fpo_data->ul_off_start, data, unsigned int);
	READ(*read_bytes, 4, data_size, fpo_data->cb_proc_size, data, unsigned int);
	READ(*read_bytes, 4, data_size, fpo_data->cdw_locals, data, unsigned int);
	READ(*read_bytes, 2, data_size, fpo_data->cdw_params, data, unsigned short);
	READ(*read_bytes, 2, data_size, fpo_data->bit_values.bit_values, data, unsigned short);

	fpo_data->bit_values.bit_values = SWAP_UINT16(fpo_data->bit_values.bit_values);

	return (*read_bytes - curr_read_bytes);
}

///////////////////////////////////////////////////////////////////////////////
static int parse_fpo_data_v2(char *data, int data_size, int *read_bytes, SFPO_DATA_V2 *fpo_data)
{
	int curr_read_bytes = *read_bytes;

	memcpy(fpo_data, data, sizeof(SFPO_DATA_V2));
	*read_bytes += sizeof(SFPO_DATA_V2);

	return (*read_bytes - curr_read_bytes);
}

///////////////////////////////////////////////////////////////////////////////
void parse_fpo_stream(void *stream, R_STREAM_FILE *stream_file)
{
	int data_size;
	char *data = 0, *ptmp = 0;
	int curr_read_bytes = 0, read_bytes = 0;
	SFPO_DATA *fpo_data = 0;
	SFPOStream *fpo_stream = 0;

	stream_file_get_size(stream_file, &data_size);
	data = (char *) malloc(data_size);
	stream_file_get_data(stream_file, data);

	fpo_stream = (SFPOStream *) stream;
	fpo_stream->fpo_data_list = r_list_new();
	curr_read_bytes = 0;
	ptmp = data;
	while (read_bytes < data_size) {
		fpo_data = (SFPO_DATA *) malloc(sizeof(SFPO_DATA));
		curr_read_bytes = parse_fpo_data(ptmp, data_size, &read_bytes, fpo_data);
		ptmp += curr_read_bytes;

		if (!curr_read_bytes) {
			free(fpo_data);
			break;
		}

		r_list_append(fpo_stream->fpo_data_list, fpo_data);
	}

	free(data);
}

///////////////////////////////////////////////////////////////////////////////
void free_fpo_stream(void *stream)
{
	SFPOStream *fpo_stream = (SFPOStream *) stream;
	RListIter *it = 0;
	SFPO_DATA *fpo_data = 0;

	it = r_list_iterator(fpo_stream->fpo_data_list);
	while (r_list_iter_next(it)) {
		fpo_data = (SFPO_DATA *) r_list_iter_get(it);
		free(fpo_data);
	}
	r_list_free(fpo_stream->fpo_data_list);
}

///////////////////////////////////////////////////////////////////////////////
void free_fpo_new_stream(void *stream)
{
	SFPONewStream *fpo_stream = (SFPONewStream *) stream;
	RListIter *it = 0;
	SFPO_DATA_V2 *fpo_data = 0;

	it = r_list_iterator(fpo_stream->fpo_data_list);
	while (r_list_iter_next(it)) {
		fpo_data = (SFPO_DATA_V2 *) r_list_iter_get(it);
		free(fpo_data);
	}
	r_list_free(fpo_stream->fpo_data_list);
}

///////////////////////////////////////////////////////////////////////////////
void parse_fpo_new_stream(void *stream, R_STREAM_FILE *stream_file)
{
	int data_size;
	char *data = 0, *ptmp = 0;
	int curr_read_bytes = 0, read_bytes = 0;
	SFPO_DATA_V2 *fpo_data = 0;
	SFPONewStream *fpo_stream = 0;

	stream_file_get_size(stream_file, &data_size);
	data = (char *) malloc(data_size);
	stream_file_get_data(stream_file, data);

	fpo_stream = (SFPONewStream *) stream;
	fpo_stream->fpo_data_list = r_list_new();
	curr_read_bytes = 0;
	ptmp = data;
	while (read_bytes < data_size) {
		fpo_data = (SFPO_DATA_V2 *) malloc(sizeof(SFPO_DATA_V2));
		curr_read_bytes = parse_fpo_data_v2(ptmp, data_size, &read_bytes, fpo_data);
		ptmp += curr_read_bytes;

		if (!curr_read_bytes) {
			free(fpo_data);
			break;
		}

		r_list_append(fpo_stream->fpo_data_list, fpo_data);
	}

	free(data);
}
