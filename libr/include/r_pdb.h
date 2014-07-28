#ifndef R2_PDB_H
#define R2_PDB_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_NAME_LEN 256

//struct R_PDB7_ROOT_STREAM;

typedef struct {
	int (*pdb_parse)(struct R_PDB *pdb);
	void (*finish_pdb_parse)(struct R_PDB *pdb);

	char file_name[FILE_NAME_LEN];
	FILE *fp;
	//R_PDB7_ROOT_STREAM *root_stream;
} R_PDB;

int init_pdb_parser(R_PDB *pdb);

#ifdef __cplusplus
}
#endif

#endif
