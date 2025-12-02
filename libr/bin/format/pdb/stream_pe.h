#ifndef PE_H
#define PE_H

void parse_pe_stream(STpiStream *ss, void *stream, R_STREAM_FILE *stream_file);
void free_pe_stream(STpiStream *ss, void *stream);

#endif // PE_H
