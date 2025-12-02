#ifndef TPI_H
#define TPI_H

///////////////////////////////////////////////////////////////////////////////
void init_tpi_stream(STpiStream *tpi_stream);

///////////////////////////////////////////////////////////////////////////////
int parse_tpi_stream(STpiStream *ss, R_STREAM_FILE *stream);

// TODO: Remove to separate file
int parse_sctring(SCString *sctr, unsigned char *leaf_data, unsigned int *read_bytes, unsigned int len);

// use r2 types here (ut16 instead of unsigned short, ut32 for unsigned int ..)
///////////////////////////////////////////////////////////////////////////////
void init_scstring(SCString *cstr, unsigned int size, char *name);

// Free a dynamically allocated simple type (tpi_idx == 0)
static inline void tpi_free_simple_type(SType *t) {
	if (t && t->tpi_idx == 0 && t->type_data.leaf_type == eLF_SIMPLE_TYPE) {
		SLF_SIMPLE_TYPE *st = (SLF_SIMPLE_TYPE *) t->type_data.type_info;
		free (st->type);
		free (st);
		free (t);
	}
}
#endif // TPI_H
