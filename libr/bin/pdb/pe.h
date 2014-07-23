#ifndef PE_H
#define PE_H

#include "types.h"

void parse_pe_stream(void *stream, R_STREAM_FILE *stream_file);
void free_pe_stream(void *stream);

#endif // PE_H
