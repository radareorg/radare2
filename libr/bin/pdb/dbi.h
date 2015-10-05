#ifndef DBI_H
#define DBI_H

void init_dbi_stream(SDbiStream *dbi_stream);
void parse_dbi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream_file);

#endif // DBI_H
