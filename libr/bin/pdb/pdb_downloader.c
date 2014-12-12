#include "pdb_downloader.h"

#include <string.h>
#include <r_util.h>

///////////////////////////////////////////////////////////////////////////////
static int download(struct SPDBDownloader *pdb_downloader)
{
	SPDBDownloaderOpt *opt = pdb_downloader->opt;
	int res = 1;
	char *curl_cmd = 0;
	int curl_cmd_len = 0;
	char *extractor_cmd = 0;
	int extractor_cmd_len = 0;
	char *abspath_to_archive = 0;
	int abspath_to_archive_len = 0;
	char *archive_name = strdup(opt->dbg_file);

	archive_name[strlen(archive_name) - 1] = '_';

	abspath_to_archive_len = strlen(archive_name) + strlen(opt->path) + 1;
	abspath_to_archive = (char *) malloc(abspath_to_archive_len);
	snprintf(abspath_to_archive, abspath_to_archive_len, "%s%s", opt->path, archive_name);

	// curl -A %1 %2/%3/%4/%5 -o %6
	// %1 - user_agent
	// %2 - symbol_server
	// %3 - dbg_file
	// %4 - guid
	// %5 - archive_name
	// %6 - absolute path to archive
	// 5 - spaces
	// 3 - /
	// 1 - for '\0'
	curl_cmd_len = strlen("curl-A-o")
			+ strlen(opt->user_agent)
			+ strlen(opt->symbol_server)
			+ strlen(opt->dbg_file)
			+ strlen(opt->guid)
			+ strlen(archive_name)
			+ strlen(abspath_to_archive)
			+ 5 + 3 + 1;

	curl_cmd = (char *) malloc(curl_cmd_len + 1);
	snprintf(curl_cmd, curl_cmd_len, "curl -A %s %s/%s/%s/%s -o %s",
			opt->user_agent,
			opt->symbol_server,
			opt->dbg_file,
			opt->guid,
			archive_name,
			abspath_to_archive);

#ifdef WIN32
	char *cabextractor = "expand";
	char *format = "%s %s %s";
	char *abspath_to_file = strdup(abspath_to_archive);
	abspath_to_file[abspath_to_archive_len - 2] = 'b';

	// extact_cmd -> %1 %2 %3
	// %1 - 'expand'
	// %2 - absolute path to archive
	// %3 - absolute path to file that will be dearchive
	// 2 - two spaces
	// 1 - for '\0'
	extractor_cmd_len = strlen(cabextractor)
			+ strlen(abspath_to_file)
			+ strlen(abspath_to_archive)
			+ 2 + 1;

	extractor_cmd = (char *) malloc(extractor_cmd_len);
	snprintf(extractor_cmd, extractor_cmd_len, format, cabextractor, abspath_to_archive, abspath_to_file);

	R_FREE(tmp);
#else
	char *cabextractor = "cabextract";
	char *format = "%s -d %s %s";

	// cabextract -d %1 %2
	// %1 - path to directory where to extract all files from cab arhcive
	// %2 - absolute path to cab archive
	// 3 - spaces
	// 2 - '-d' option
	// 1 - for '\0'
	extractor_cmd_len  = strlen(cabextractor)
			+ strlen(opt->path)
			+ strlen(abspath_to_archive) + 3 + 2 + 1;
	extractor_cmd = (char *) malloc(extractor_cmd_len);
	snprintf(extractor_cmd, extractor_cmd_len, format, cabextractor, opt->path, abspath_to_archive);
#endif

	if (r_sys_cmd(curl_cmd) == -1) {
		printf("curl has not been finish with sucess\n");
		res = 0;
	}

	if ((res) && (r_sys_cmd(extractor_cmd) == -1)) {
		printf("cab extrach has not been finished with sucess\n");
		res = 0;
	}

	r_file_rm(abspath_to_archive);

	R_FREE(archive_name);
	R_FREE(curl_cmd);
	R_FREE(extractor_cmd);
	R_FREE(abspath_to_archive);

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
