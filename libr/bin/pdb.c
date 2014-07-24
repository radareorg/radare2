#include <r_pdb.h>

#include <string.h>

#define PDB2_SIGNATURE "Microsoft C/C++ program database 2.00\r\n\032JG\0\0"
#define PDB7_SIGNATURE "Microsoft C/C++ MSF 7.00\r\n\x1ADS\0\0\0"
#define PDB7_SIGNATURE_LEN 40
#define PDB2_SIGNATURE_LEN 51

static int pdb7_parse(R_PDB *pdb)
{
	printf("pdb7_parse()\n");
	return 0;
}

static void finish_pdb_parse(R_PDB *pdb)
{
	fclose(pdb->fp);
	printf("finish_pdb_parse()\n");
}

int init_pdb_parser(R_PDB *pdb)
{
	char *signature = 0;
	int bytes_read = 0;

	if (!pdb) {
		printf("struct R_PDB is not correct\n");
		goto error;
	}

	pdb->fp = fopen(pdb->file_name, "r");
	if (!pdb->fp) {
		printf("file %s can not be open\n", pdb->file_name);
		goto error;
	}

	signature = (char *)malloc(sizeof(char) * PDB7_SIGNATURE_LEN);
	if (!signature) {
		printf("memory allocation error\n");
		goto error;
	}

	bytes_read = fread(signature, 1, PDB7_SIGNATURE_LEN, pdb->fp);
	if (bytes_read != PDB7_SIGNATURE_LEN) {
		printf("file reading error\n");
		goto error;
	}

	fseek(pdb->fp, 0, SEEK_SET);

	if (memcmp(signature, PDB7_SIGNATURE, PDB7_SIGNATURE_LEN)) {
		pdb->pdb_parse =pdb7_parse;
	} else {
		printf("unsupported pdb format\n");
		goto error;
	}

	if (signature) {
		free(signature);
		signature = 0;
	}

	pdb->finish_pdb_parse = finish_pdb_parse;
	printf("init_pdb_parser() finish with success\n");
	return 1;

error:
	if (signature) {
		free(signature);
		signature = 0;
	}

	return 0;
}
