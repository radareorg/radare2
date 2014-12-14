#include "pdb_downloader.h"

#include <string.h>
#include <r_util.h>

///////////////////////////////////////////////////////////////////////////////
static int download(struct SPDBDownloader *pdb_downloader)
{
	SPDBDownloaderOpt *opt = pdb_downloader->opt;
	int res = 1;
	char *curl_cmd = 0;
	char *extractor_cmd = 0;
	char *abspath_to_archive = 0;
	int abspath_to_archive_len = 0;
	char *archive_name;
	int archive_name_len;
	if (!opt->dbg_file || !*opt->dbg_file) {
		// no pdb debug file
		return 0;
	}
	// dbg_file len is > 0
	archive_name_len = strlen (opt->dbg_file);
	archive_name = malloc (archive_name_len+1);
	memcpy (archive_name, opt->dbg_file, archive_name_len+1);

	archive_name[archive_name_len-1] = '_';

	abspath_to_archive_len = archive_name_len + strlen (opt->path) + 2;
	abspath_to_archive = r_str_newf ("%s%s%s", opt->path,
		R_SYS_DIR, archive_name);
	curl_cmd = r_str_newf ("curl -A %s %s/%s/%s/%s -o %s",
			opt->user_agent,
			opt->symbol_server,
			opt->dbg_file,
			opt->guid,
			archive_name,
			abspath_to_archive);
#if __WINDOWS__
	const char *cabextractor = "expand";
	const char *format = "%s %s %s";
	char *abspath_to_file = strdup (abspath_to_archive);
	abspath_to_file[abspath_to_archive_len - 2] = 'b';

	// extact_cmd -> %1 %2 %3
	// %1 - 'expand'
	// %2 - absolute path to archive
	// %3 - absolute path to file that will be dearchive
	extractor_cmd = r_str_newf (format, cabextractor,
		abspath_to_archive, abspath_to_file);
#else
	const char *cabextractor = "cabextract";
	const char *format = "%s -d %s %s";

	// cabextract -d %1 %2
	// %1 - path to directory where to extract all files from cab arhcive
	// %2 - absolute path to cab archive
	extractor_cmd = r_str_newf (format,
		cabextractor, opt->path, abspath_to_archive);
#endif
	if (r_sys_cmd (curl_cmd) != 0) {
		eprintf("curl has not been finish with sucess\n");
		res = 0;
	}

	if (res && (r_sys_cmd (extractor_cmd) != 0)) {
		eprintf ("cab extrach has not been finished with sucess\n");
		res = 0;
	}
	r_file_rm (abspath_to_archive);
	R_FREE (archive_name);
	R_FREE (curl_cmd);
	R_FREE (extractor_cmd);
	R_FREE (abspath_to_archive);
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
