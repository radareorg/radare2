#ifndef R2_PDB_H
#define R2_PDB_H

#define _R_LIST_C
#include "r_util.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_NAME_LEN 256

struct R_PDB7_ROOT_STREAM;

typedef struct r_pdb_t {
	bool (*pdb_parse)(struct r_pdb_t *pdb);
	void (*finish_pdb_parse)(struct r_pdb_t *pdb);
	void (*print_types)(const struct r_pdb_t *pdb, PJ *pj, int mode);
//	FILE *fp;
	PrintfCallback cb_printf;
	struct R_PDB7_ROOT_STREAM *root_stream;
	void *stream_map;
	RList *pdb_streams;
	RList *pdb_streams2;
	RBuffer *buf; // mmap of file
//	int curr;

	void (*print_gvars)(struct r_pdb_t *pdb, ut64 img_base, PJ *pj, int format);
} RPdb;

R_API bool init_pdb_parser(RPdb *pdb, const char *filename);
R_API bool init_pdb_parser_with_buf(RPdb *pdb, RBuffer *buf);

#ifdef __cplusplus
}
#endif

#endif
