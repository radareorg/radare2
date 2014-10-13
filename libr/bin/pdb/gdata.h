#ifndef GDATA_H
#define GDATA_H

#include "types.h"

void parse_gdata_stream(void *stream, R_STREAM_FILE *stream_file);
void free_gdata_stream(void *stream);

#endif // GDATA_H
