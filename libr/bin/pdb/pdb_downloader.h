#ifndef PDB_DOWNLOADER_H
#define PDB_DOWNLOADER_H
#include <r_types.h>
#include <r_core.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct SPDBOptions {
	char *user_agent;
	char *symbol_server;
	int extract;
} SPDBOptions;

typedef struct SPDBDownloaderOpt {
	char *user_agent;
	char *symbol_server;
	char *dbg_file;
	char *guid;
	char *path;
	int extract;
} SPDBDownloaderOpt;

typedef struct SPDBDownloader {
	SPDBDownloaderOpt *opt;

	int (*download)(struct SPDBDownloader *pdb_downloader);
} SPDBDownloader;

///
/// \brief initialization of pdb downloader by SPDBDownloaderOpt
/// \param opt PDB options
/// \param pdb_downloader PDB downloader that will be init
///
void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pdb_downloader);

///
/// \brief deinitialization of PDB downloader
/// \param pdb_downloader PDB downloader that will be deinit
///
void deinit_pdb_downloader(SPDBDownloader *pdb_downloader);

///
/// \brief download PDB file
R_API int r_bin_pdb_download (RCore* core, int isradjson, int* actions_done, SPDBOptions* options);

#ifdef __cplusplus
}
#endif

#endif
