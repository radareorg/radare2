#ifndef TPI_H
#define TPI_H

#include "types.h"

///////////////////////////////////////////////////////////////////////////////
void init_tpi_stream(STpiStream *tpi_stream);

///////////////////////////////////////////////////////////////////////////////
int parse_tpi_stream(void *parsed_pdb_stream, R_STREAM_FILE *stream);

// TODO: Remove to separate file
int parse_sctring(SCString *sctr, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len);

// use r2 types here (ut16 instead of unsigned short, ut32 for unsigned int ..)
///////////////////////////////////////////////////////////////////////////////
void init_scstring(SCString *cstr, unsigned int size, char *name);
#endif // TPI_H
