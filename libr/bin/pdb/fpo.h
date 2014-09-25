#ifndef FPO_H
#define FPO_H

#include "types.h"

void free_fpo_stream(void *stream);
void parse_fpo_stream(void *stream, R_STREAM_FILE *stream_file);

#endif // FPO_H
