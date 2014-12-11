#include "pdb_downloader.h"

#include <string.h>
#include <r_types.h>

///////////////////////////////////////////////////////////////////////////////
static int download(struct SPDBDownloader *pdb_downloader)
{
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pdb_downloader)
{
	pdb_downloader->opt = (SPDBDownloaderOpt *) malloc(sizeof(SPDBDownloaderOpt));
	pdb_downloader->opt->dbg_file = strdup(opt->dbg_file);
	pdb_downloader->opt->guid = strdup(opt->guid);
	pdb_downloader->opt->symbol_server = strdup(opt->symbol_server);
	pdb_downloader->opt->user_agent = strdup(opt->user_agent);

	pdb_downloader->download = download;
}

///////////////////////////////////////////////////////////////////////////////
void deinit_pdb_downloader(SPDBDownloader *pdb_downloader)
{
	R_FREE(pdb_downloader->opt->dbg_file);
	R_FREE(pdb_downloader->opt->guid);
	R_FREE(pdb_downloader->opt->symbol_server);
	R_FREE(pdb_downloader->opt->user_agent);
	R_FREE(pdb_downloader->opt);
	pdb_downloader->download = 0;
}
