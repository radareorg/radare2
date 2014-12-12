#ifndef PDB_DOWNLOADER_H
#define PDB_DOWNLOADER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SPDBDownloaderOpt {
	char *user_agent;
	char *symbol_server;
	char *dbg_file;
	char *guid;
	char *path;
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

#ifdef __cplusplus
}
#endif

#endif
