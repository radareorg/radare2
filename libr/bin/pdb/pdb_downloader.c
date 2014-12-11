#include "pdb_downloader.h"

#include <string.h>
//#include <r_types.h>
#include <r_util.h>

///////////////////////////////////////////////////////////////////////////////
static int download(struct SPDBDownloader *pdb_downloader)
{
	int res = 1;
	SPDBDownloaderOpt *opt = pdb_downloader->opt;
	char *curl_cmd = 0;
	int curl_cmd_len = strlen("curl -A ")
			+ strlen(opt->user_agent)
			+ strlen(opt->symbol_server)
			+ 3 * strlen(opt->dbg_file)
			+ strlen(opt->guid)
			+ strlen(opt->path)
			+ 4 + 1; // 3- / - symbol_server/dbg_file/guid/archive_name
	char *extractor_cmd = 0;
	int extractor_cmd_len = 0;

	char *abspath = 0;
	int abspath_len = strlen(opt->dbg_file) + strlen(opt->path) + 1;

	char *archive_name = strdup(opt->dbg_file);
	archive_name[strlen(archive_name) - 1] = '_';

	abspath = (char *) malloc(abspath_len);
	snprintf(abspath, abspath_len, "%s%s", opt->path, opt->dbg_file);

#ifdef WIN32
	char *cabextractor = "expand";
	#error ADD SUPPORT FOR WINDOWS
#else
	char *cabextractor = "cabextract";
	char *format = "%s -d %s %s";
	extractor_cmd_len  = strlen(cabextractor) + 2;
#endif

	curl_cmd = (char *) malloc(curl_cmd_len + 1);
	curl_cmd[curl_cmd_len] = '\0';
	snprintf(curl_cmd, curl_cmd_len, "curl -A %s %s/%s/%s/%s -o %s/%s",
			opt->user_agent,
			opt->symbol_server,
			opt->dbg_file,
			opt->guid,
			archive_name,
			opt->path,
			archive_name);

	extractor_cmd = (char *) malloc(extractor_cmd_len);
	extractor_cmd[extractor_cmd_len] = '\0';
	snprintf(extractor_cmd, extractor_cmd_len, format, cabextractor, opt->path, archive_name);

	if (r_sys_cmd(curl_cmd) == -1) {
		printf("curl has not been finish with sucess\n");
		res = 0;
	}

	r_file_rm(abspath);

	if (r_sys_cmd(extractor_cmd) == -1) {
		printf("cab extrach has not been finished with sucess\n");
		res = 0;
	}

	R_FREE(archive_name);
	R_FREE(curl_cmd);
	R_FREE(extractor_cmd);
	R_FREE(abspath);

	return res;
}

///////////////////////////////////////////////////////////////////////////////
void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pdb_downloader)
{
	pdb_downloader->opt = (SPDBDownloaderOpt *) malloc(sizeof(SPDBDownloaderOpt));
	pdb_downloader->opt->dbg_file = strdup(opt->dbg_file);
	pdb_downloader->opt->guid = strdup(opt->guid);
	pdb_downloader->opt->symbol_server = strdup(opt->symbol_server);
	pdb_downloader->opt->user_agent = strdup(opt->user_agent);
	pdb_downloader->opt->path = strdup(opt->path);

	pdb_downloader->download = download;
}

///////////////////////////////////////////////////////////////////////////////
void deinit_pdb_downloader(SPDBDownloader *pdb_downloader)
{
	R_FREE(pdb_downloader->opt->dbg_file);
	R_FREE(pdb_downloader->opt->guid);
	R_FREE(pdb_downloader->opt->symbol_server);
	R_FREE(pdb_downloader->opt->user_agent);
	R_FREE(pdb_downloader->opt->path);
	R_FREE(pdb_downloader->opt);
	pdb_downloader->download = 0;
}
