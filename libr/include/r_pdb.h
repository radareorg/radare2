#ifndef R2_PDB_H
#define R2_PDB_H

#ifdef __cplusplus
extern "C" {
#endif

#define FILE_NAME_LEN 256

typedef struct {

	int (*pdb_parse)();
	void (*finish_pdb_parse)();

	char file_name[FILE_NAME_LEN];
} R_PDB;

int init_pdb_parser(R_PDB *pdb);

#ifdef __cplusplus
}
#endif

#endif
