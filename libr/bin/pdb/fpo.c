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
void parse_fpo_stream(void *stream, R_STREAM_FILE *stream_file)
{
	int pn_start, off_start;
	int data_size;
	char *data = 0, *ptmp = 0;
	int curr_read_bytes = 0, read_bytes = 0;
	SFPO_DATA *fpo_data = 0;
	SFPOStream *fpo_stream = 0;

	// TODO: add to stream_file.h function get_data and get_data_size...
	GET_PAGE(pn_start, off_start, stream_file->pos, stream_file->page_size);
	data_size = stream_file->end - off_start;
	data = (char *) malloc(data_size);
	curr_read_bytes = stream_file_tell(stream_file);
	stream_file_seek(stream_file, 0, 0);
	stream_file_read(stream_file, -1, data);
	stream_file_seek(stream_file, curr_read_bytes, 0);

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
}
