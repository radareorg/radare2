#ifndef OMAP_H
#define OMAP_H

#include "types.h"

void parse_omap_stream(void *stream, R_STREAM_FILE *stream_file);
void free_omap_stream(void *stream);
int omap_remap(void *stream, int address);

#endif // OMAP_H
