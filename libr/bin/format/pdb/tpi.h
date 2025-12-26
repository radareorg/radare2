#ifndef TPI_H
#define TPI_H

void init_tpi_stream(STpiStream *tpi_stream);
bool parse_tpi_stream(STpiStream *ss, R_STREAM_FILE *stream);
// TODO: Remove to separate file
int parse_sctring(SCString *sctr, ut8 *leaf_data, ut32 *read_bytes, ut32 len);
void init_scstring(SCString *cstr, ut32 size, char *name);

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
