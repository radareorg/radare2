#ifndef R2_PDB_H
#define R2_PDB_H

#define _R_LIST_C
#include "r_util.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_NAME_LEN 256

struct RList;
struct R_PDB;
struct R_PDB7_ROOT_STREAM;

typedef struct {
	int (*pdb_parse)(struct R_PDB *pdb);
	void (*finish_pdb_parse)(struct R_PDB *pdb);
	void (*print_types)(struct R_PDB *pdb);

	char file_name[FILE_NAME_LEN];
	FILE *fp;
	struct R_PDB7_ROOT_STREAM *root_stream;
	void *stream_map;
	RList *pdb_streams;
	RList *pdb_streams2;

	void (*print_gvars)(struct R_PDB *pdb, int img_base);
} R_PDB;

int init_pdb_parser(R_PDB *pdb);

#ifdef __cplusplus
}
#endif

#endif
