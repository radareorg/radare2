/* radare - LGPL - Copyright 2014-2020 - inisider */

#include <string.h>
#include <r_util.h>
#include <r_core.h>
#include "pdb_downloader.h"

static bool checkExtract(void) {
#if __WINDOWS__
	return r_sys_cmd ("expand -? >nul") == 0;
#else
	return r_sys_cmd ("cabextract -v > /dev/null") == 0;
#endif
}

static bool download_and_write(SPDBDownloaderOpt *opt, const char *file) {
	char *dir = r_str_newf ("%s%s%s%s%s",
		opt->symbol_store_path, R_SYS_DIR,
		opt->dbg_file, R_SYS_DIR,
		opt->guid);
	if (!r_sys_mkdirp (dir)) {
		free (dir);
		return false;
	}
	char *url = r_str_newf ("%s/%s/%s/%s", opt->symbol_server, opt->dbg_file, opt->guid, file);
	char *path = r_str_newf ("%s%s%s", dir, R_SYS_DIR, opt->dbg_file);
#if __WINDOWS__
	if (r_str_startswith (url, "\\\\")) { // Network path
		LPCWSTR origin = r_utf8_to_utf16 (url);
		LPCWSTR dest = r_utf8_to_utf16 (path);
		BOOL ret = CopyFileW (origin, dest, FALSE);
		free (dir);
		free (path);
		free (origin);
		free (dest);
		return ret;
	}
#endif
	int len;
	char *file_buf = r_socket_http_get (url, NULL, &len);
	free (url);
	if (!len || R_STR_ISEMPTY (file_buf)) {
		free (dir);
		free (file_buf);
		free (path);
		return false;
	}
	FILE *f = fopen (path, "wb");
	if (f) {
		fwrite (file_buf, sizeof (char), (size_t)len, f);
		fclose (f);
	}
	free (dir);
	free (path);
	free (file_buf);
	return true;
}

static int download(struct SPDBDownloader *pd) {
	SPDBDownloaderOpt *opt = pd->opt;
	int res = 0;
	int cmd_ret;

	if (!opt->dbg_file || !*opt->dbg_file) {
		// no pdb debug file
		return 0;
	}

	char *abspath_to_file = r_str_newf ("%s%s%s%s%s%s%s",
		opt->symbol_store_path, R_SYS_DIR,
		opt->dbg_file, R_SYS_DIR,
		opt->guid, R_SYS_DIR,
		opt->dbg_file);

	if (r_file_exists (abspath_to_file)) {
		eprintf ("File already downloaded.\n");
		free (abspath_to_file);
		return 1;
	}

	if (checkExtract () || opt->extract == 0) {
		char *extractor_cmd = NULL;
		char *archive_name = strdup (opt->dbg_file);
		archive_name[strlen (archive_name) - 1] = '_';
		char *abspath_to_archive = r_str_newf ("%s%s%s%s%s%s%s",
			opt->symbol_store_path, R_SYS_DIR,
			opt->dbg_file, R_SYS_DIR,
			opt->guid, R_SYS_DIR,
			archive_name);

		eprintf ("Attempting to download compressed pdb in %s\n", abspath_to_archive);
		char *abs_arch_esc = r_str_escape_sh (abspath_to_archive);
#if __WINDOWS__
		char *abs_file_esc = r_str_escape_sh (abspath_to_file);
		// expand %1 %2
		// %1 - absolute path to archive
		// %2 - absolute path to file that will be dearchive
		extractor_cmd = r_str_newf ("expand \"%s\" \"%s\"", abs_arch_esc, abs_file_esc);
		free (abs_file_esc);
#else
		char *abspath_to_dir = r_file_dirname (abspath_to_archive);
		char *abs_dir_esc = r_str_escape_sh (abspath_to_dir);
		// cabextract -d %1 %2
		// %1 - path to directory where to extract all files from cab archive
		// %2 - absolute path to cab archive
		extractor_cmd = r_str_newf ("cabextract -d \"%s\" \"%s\"", abs_arch_esc, abs_dir_esc);
		free (abs_dir_esc);
		free (abspath_to_dir);
#endif
		free (abs_arch_esc);
		res = download_and_write (opt, archive_name);

		if (opt->extract > 0 && res) {
			eprintf ("Attempting to decompress pdb\n");
			if (res && ((cmd_ret = r_sys_cmd (extractor_cmd)) != 0)) {
				eprintf ("cab extractor exited with error %d\n", cmd_ret);
				res = 0;
			}
			r_file_rm (abspath_to_archive);
		}
		free (archive_name);
		free (abspath_to_archive);
		free (extractor_cmd);
	}
	if (res == 0) {
		eprintf ("Falling back to uncompressed pdb\n");
		eprintf ("Attempting to download uncompressed pdb in %s\n", abspath_to_file);
		res = download_and_write (opt, opt->dbg_file);
	}
	free (abspath_to_file);
	return res;
}

void init_pdb_downloader(SPDBDownloaderOpt *opt, SPDBDownloader *pd) {
	pd->opt = R_NEW0 (SPDBDownloaderOpt);
	if (!pd->opt) {
		pd->download = 0;
		eprintf ("Cannot allocate memory for SPDBDownloaderOpt.\n");
		return;
	}
	pd->opt->dbg_file = strdup (opt->dbg_file);
	pd->opt->guid = strdup (opt->guid);
	pd->opt->symbol_server = strdup (opt->symbol_server);
	pd->opt->user_agent = strdup (opt->user_agent);
	pd->opt->symbol_store_path = strdup (opt->symbol_store_path);
	pd->opt->extract = opt->extract;
	pd->download = download;
}

void deinit_pdb_downloader(SPDBDownloader *pd) {
	R_FREE (pd->opt->dbg_file);
	R_FREE (pd->opt->guid);
	R_FREE (pd->opt->symbol_server);
	R_FREE (pd->opt->user_agent);
	R_FREE (pd->opt->symbol_store_path);
	R_FREE (pd->opt);
	pd->download = 0;
}

static bool is_valid_guid(const char *guid) {
	if (!guid) {
		return false;
	}
	size_t i;
	for (i = 0; guid[i]; i++) {
		if (!isxdigit ((unsigned char)guid[i])) {
			return false;
		}
	}
	return i >= 33; // len of GUID and age
}

int r_bin_pdb_download(RCore *core, PJ *pj, int isradjson, SPDBOptions *options) {
	int ret;
	SPDBDownloaderOpt opt;
	SPDBDownloader pdb_downloader;
	RBinInfo *info = r_bin_get_info (core->bin);

	if (!info || !info->debug_file_name) {
		eprintf ("Can't find debug filename\n");
		return 1;
	}

	if (!is_valid_guid (info->guid)) {
		eprintf ("Invalid GUID for file\n");
		return 1;
	}

	if (!options || !options->symbol_server || !options->user_agent) {
		eprintf ("Can't retrieve pdb configurations\n");
		return 1;
	}

	opt.dbg_file = (char*) r_file_basename (info->debug_file_name);
	opt.guid = info->guid;
	opt.symbol_server = options->symbol_server;
	opt.user_agent = options->user_agent;
	opt.symbol_store_path = options->symbol_store_path;
	opt.extract = options->extract;

	init_pdb_downloader (&opt, &pdb_downloader);
	ret = pdb_downloader.download ? pdb_downloader.download (&pdb_downloader) : 0;
	if (isradjson) {
		pj_ko (pj, "pdb");
		pj_ks (pj, "file", opt.dbg_file);
		pj_kb (pj, "download", (bool) ret);
		pj_end (pj);
	} else {
		r_cons_printf ("PDB \"%s\" download %s\n",
		        opt.dbg_file, ret ? "success" : "failed");
	}
	deinit_pdb_downloader (&pdb_downloader);

	return !ret;
}
