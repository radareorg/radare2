#ifndef FPO_H
#define FPO_H

void free_fpo_stream(void *stream);
void parse_fpo_stream(void *stream, R_STREAM_FILE *stream_file);

void free_fpo_new_stream(void *stream);
void parse_fpo_new_stream(void *stream, R_STREAM_FILE *stream_file);

#endif // FPO_H
