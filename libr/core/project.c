/* radare - LGPL - Copyright 2010-2016 - pancake, maijin */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static bool r_core_project_load_xrefs(RCore *core, const char *prjName);

static bool is_valid_project_name (const char *name) {
	int i;
	for (i=0; name[i]; i++) {
		switch (name[i]) {
		case '\\': // for w32
		case '.':
		case '_':
		case ':':
			continue;
		}
		if (name[i] >= 'a' && name[i] <= 'z')
			continue;
		if (name[i] >= 'A' && name[i] <= 'Z')
			continue;
		if (name[i] >= '0' && name[i] <= '9')
			continue;
		return false;
	}
	return true;
}

static char *r_core_project_file(RCore *core, const char *file) {
	const char *magic = "# r2 rdb project file";
	char *data, *prjfile;
	if (r_file_is_abspath (file)) {
		prjfile = strdup (file);
	} else {
		if (!is_valid_project_name (file)) {
			return NULL;
		}
		prjfile = r_file_abspath (r_config_get (
			core->config, "dir.projects"));
		prjfile = r_str_concat (prjfile, R_SYS_DIR);
		prjfile = r_str_concat (prjfile, file);
		if (r_file_is_directory (prjfile)) {
			prjfile = r_str_concat (prjfile, R_SYS_DIR"rc");
		}
	}
	data = r_file_slurp (prjfile, NULL);
	if (data) {
		if (strncmp (data, magic, strlen (magic))) {
			R_FREE (prjfile);
		}
	}
	free (data);
	return prjfile;
}

static int r_core_project_init(RCore *core) {
	char *prjdir = r_file_abspath (r_config_get (
		core->config, "dir.projects"));
	int ret = r_sys_mkdirp (prjdir);
	if (!ret) {
		eprintf ("Cannot mkdir dir.projects\n");
	}
	free (prjdir);
	return ret;
}

static bool r_core_is_project(RCore *core, const char *name) {
	bool ret = false;
	if (name && *name && *name != '.') {
		char *path = r_core_project_file (core, name);
		if (!path) {
			return false;
		}
		path = r_str_concat (path, ".d");
		if (r_file_is_directory (path)) {
			ret = true;
		}
		free (path);
	}
	return ret;
}

R_API int r_core_project_cat(RCore *core, const char *name) {
	char *path = r_core_project_file (core, name);
	if (path) {
		char *data = r_file_slurp (path, NULL);
		if (data) {
			r_cons_println (data);
			free (data);
		}
	}
	free (path);
	return 0;
}

R_API int r_core_project_list(RCore *core, int mode) {
	RListIter *iter;
	RList *list;
	int isfirst = 1;
	char *foo, *path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	if (!path) {
		return 0;
	}
	list = r_sys_dir (path);
	switch (mode) {
	case 'j':
		r_cons_printf ("[");
		r_list_foreach (list, iter, foo) {
			// todo. escape string
			if (r_core_is_project (core, foo)) {
				r_cons_printf ("%s\"%s\"",
					isfirst?"":",", foo);
				isfirst = 0;
			}
		}
		r_cons_printf ("]\n");
		break;
	default:
		r_list_foreach (list, iter, foo) {
			if (r_core_is_project (core, foo)) {
				r_cons_println (foo);
			}
		}
		break;
	}
	r_list_free (list);
	free (path);
	return 0;
}

R_API int r_core_project_delete(RCore *core, const char *prjfile) {
	char *path;
	if (r_sandbox_enable (0)) {
		eprintf ("Cannot delete project in sandbox mode\n");
		return 0;
	}
	path = r_core_project_file (core, prjfile);
	if (!path) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	if (r_core_is_project (core, prjfile)) {
		// rm project file
		r_file_rm (path);
		eprintf ("rm %s\n", path);
		path = r_str_concat (path, ".d");
		if (r_file_is_directory (path)) {
			char *f;
			RListIter *iter;
			RList *files = r_sys_dir (path);
			r_list_foreach (files, iter, f) {
				char *filepath = r_str_concat (strdup (path), R_SYS_DIR);
				filepath =r_str_concat (filepath, f);
				if (!r_file_is_directory (filepath)) {
					eprintf ("rm %s\n", filepath);
					r_file_rm (filepath);
				}
				free (filepath);
			}
			r_file_rm (path);
			eprintf ("rm %s\n", path);
			r_list_free (files);
		}
		// TODO: remove .d directory (BEWARE OF ROOT RIMRAFS!)
		// TODO: r_file_rmrf (path);
	}
	free (path);
	return 0;
}

static bool r_core_rop_load(RCore *core, const char *prjfile) {
	char *path, *db = NULL, *path_ns;
	bool found = 0;
	SdbListIter *it;
	int prjType = 0;
	SdbNs *ns;

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	Sdb *nop_db = sdb_ns (rop_db, "nop", false);
	Sdb *mov_db = sdb_ns (rop_db, "mov", false);
	Sdb *const_db = sdb_ns (rop_db, "const", false);
	Sdb *arithm_db = sdb_ns (rop_db, "arithm", false);
	Sdb *arithmct_db = sdb_ns (rop_db, "arithm_ct", false);

	char *rcPath = r_core_project_file (core, prjfile);
	char *prjDir = r_file_dirname (rcPath);

	if (!prjfile || !*prjfile) {
		return false;
	}
	if (r_str_endswith (prjfile, "/rc")) {
		// XXX
		eprintf ("ENDS WITH\n");
		prjType = 1;
		path = strdup (prjfile);
		path [strlen (path) - 3] = 0;
	} else if (r_file_fexists ("%s/rc", prjDir, prjfile)) {
		prjType = 1;
		path = r_str_newf ("%s/", prjDir, prjfile);
	} else {
		if (*prjfile == '/') {
			db = r_str_newf ("%s.d", prjfile);
			if (!db) {
				return false;
			}
			path = strdup (db);
		} else {
			db = r_str_newf ("%s/%s.d", prjDir, prjfile);
			if (!db) {
				return false;
			}
			path = r_file_abspath (db);
		}
	}

	if (!path) {
		free (db);
		return false;
	}
	if (rop_db) {
		ls_foreach (core->sdb->ns, it, ns){
			if (ns->sdb == rop_db) {
				ls_delete (core->sdb->ns, it);
				found = true;
				break;
			}
		}
	}
	if (!found) {
		sdb_free (rop_db);
	}
	rop_db = sdb_new (path, "rop", 0);
	if (!rop_db) {
		free (db);
		free (path);
		return false;
	}
	sdb_ns_set (core->sdb, "rop", rop_db);

	path_ns = r_str_newf ("%s" R_SYS_DIR "rop", path);
	nop_db = sdb_new (path_ns, "nop", 0);
	sdb_ns_set (rop_db, "nop", nop_db);

	mov_db = sdb_new (path_ns, "mov", 0);
	sdb_ns_set (rop_db, "mov", mov_db);

	const_db = sdb_new (path_ns, "const", 0);
	sdb_ns_set (rop_db, "const", const_db);

	arithm_db = sdb_new (path_ns, "arithm", 0);
	sdb_ns_set (rop_db, "arithm", arithm_db);

	arithmct_db = sdb_new (path_ns, "arithm_ct", 0);
	sdb_ns_set (rop_db, "arithm_ct", arithmct_db);

	free (path);
	free (path_ns);
	free (db);
	return true;
}

R_API bool r_core_project_load(RCore *core, const char *prjName, const char *rcpath) {
	(void)r_core_rop_load (core, prjName);
	(void)r_core_project_load_xrefs (core, prjName);
	return r_core_cmd_file (core, rcpath);
}

R_API int r_core_project_open(RCore *core, const char *prjfile) {
	int askuser = 1;
	int ret, close_current_session = 1;
	char *prj, *filepath;
	if (!prjfile || !*prjfile) {
		return false;
	}
	const bool cfg_fortunes = r_config_get_i (core->config, "cfg.fortunes");
	const bool scr_interactive = r_config_get_i (core->config, "scr.interactive");
	const bool scr_prompt = r_config_get_i (core->config, "scr.prompt");
	prj = r_core_project_file (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	filepath = r_core_project_info (core, prj);
	//eprintf ("OPENING (%s) from %s\n", prj, r_config_get (core->config, "file.path"));
	/* if it is not an URI */
	if (!filepath) {
		eprintf ("Cannot retrieve information for project '%s'\n", prj);
		free (prj);
		return false;
	}
	if (!strstr (filepath, "://")) {
		/* check if path exists */
		if (!r_file_exists (filepath)) {
			eprintf ("Cannot find file '%s'\n", filepath);
			free (prj);
			free (filepath);
			return false;
		}
	}
	if (!strcmp (prjfile, r_config_get (core->config, "prj.name"))) {
		//eprintf ("Reloading project\n");
		askuser = 0;
#if 0
		free (prj);
		free (filepath);
		return false;
#endif
	}
	if (askuser) {
		if (r_config_get_i (core->config, "scr.interactive")) {
			close_current_session = r_cons_yesno ('y', "Close current session? (Y/n)");
		}
	}
	if (close_current_session) {
		RCoreFile *fh;
		// delete
		r_core_file_close_fd (core, -1);
		r_io_close_all (core->io);
		r_anal_purge (core->anal);
		r_flag_unset_all (core->flags);
		r_bin_file_delete_all (core->bin);
		// open new file
		// TODO: handle read/read-write mode
		// TODO: handle mapaddr (io.maps are not saved in projects yet)
		fh = r_core_file_open (core, filepath, 0, 0);
		if (!fh) {
			eprintf ("Cannot open file '%s'\n", filepath);
			free (filepath);
			free (prj);
			return false;
		}
		// TODO: handle load bin info or not
		// TODO: handle base address
		r_core_bin_load (core, filepath, UT64_MAX);
	}
	/* load sdb stuff in here */
	ret = r_core_project_load (core, prjfile, prj);
	r_config_set_i (core->config, "cfg.fortunes", cfg_fortunes);
	r_config_set_i (core->config, "scr.interactive", scr_interactive);
	r_config_set_i (core->config, "scr.prompt", scr_prompt);
	r_config_bump (core->config, "asm.arch");
	free (filepath);
	free (prj);
	return ret;
}

R_API char *r_core_project_info(RCore *core, const char *prjfile) {
	FILE *fd;
	char buf[256], *file = NULL;
	char *prj = r_core_project_file (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return NULL;
	}
	fd = r_sandbox_fopen (prj, "r");
	if (fd) {
		for (;;) {
			fgets (buf, sizeof (buf), fd);
			if (feof (fd)) {
				break;
			}
			if (!strncmp (buf, "\"e file.path = ", 15)) {
				buf[strlen (buf) - 2] = 0;
				file = r_str_new (buf + 15);
				break;
			}
			// TODO: deprecate before 1.0
			if (!strncmp (buf, "e file.path = ", 14)) {
				buf[strlen (buf) - 1] = 0;
				file = r_str_new (buf + 14);
				break;
			}
		}
		fclose (fd);
	} else {
		eprintf ("Cannot open project info (%s)\n", prj);
	}
#if 0
	if (file) {
		r_cons_printf ("Project: %s\n", prj);
		r_cons_printf ("FilePath: %s\n", file);
	}
#endif
	free (prj);
	return file;
}

R_API bool r_core_project_save_rdb(RCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold, tmp;

	if (!file || *file == '\0')
		return false;

	filename = r_str_word_get_first (file);
	fd = r_sandbox_open (file, O_BINARY|O_RDWR|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		free (filename);
		return false;
	}

	hl = r_cons_singleton ()->highlight;
	if (hl) {
		ohl = strdup (hl);
		r_cons_highlight (NULL);
	}

	fdold = r_cons_singleton ()->fdout;
	r_cons_singleton ()->fdout = fd;
	r_cons_singleton ()->is_interactive = false;

	r_str_write (fd, "# r2 rdb project file\n");

	if (opts & R_CORE_PRJ_FLAGS) {
		r_str_write (fd, "# flags\n");
		tmp = core->flags->space_idx;
		core->flags->space_idx = -1;
		r_flag_list (core->flags, true, NULL);
		core->flags->space_idx = tmp;
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_EVAL) {
		r_str_write (fd, "# eval\n");
		r_config_list (core->config, NULL, true);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_IO_MAPS) {
		r_core_cmd (core, "om*", 0);
		r_cons_flush ();
	}
	{
		r_core_cmd (core, "fz*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_SECTIONS) {
		r_str_write (fd, "# sections\n");
		r_io_section_list (core->io, core->offset, 1);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_META) {
		r_str_write (fd, "# meta\n");
		r_meta_list (core->anal, R_META_TYPE_ANY, 1);
		r_cons_flush ();
		r_core_cmd (core, "fV*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_XREFS) {
		r_core_cmd (core, "ax*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_FCNS) {
		r_core_cmd (core, "afl*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_FLAGS) {
		r_core_cmd (core, "f.**", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_DBG_BREAK) {
		r_core_cmd (core, "db*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_HINTS) {
		r_core_cmd (core, "ah*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_TYPES) {
		r_str_write (fd, "# types\n");
		r_core_cmd (core, "t*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_MACROS) {
		r_str_write (fd, "# macros\n");
		r_core_cmd (core, "(*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_ANAL_SEEK) {
		r_cons_printf ("# seek\n"
			"s 0x%08"PFMT64x"\n", core->offset);
		r_cons_flush ();
	}

	r_cons_singleton ()->fdout = fdold;
	r_cons_singleton ()->is_interactive = true;

	if (ohl) {
		r_cons_highlight (ohl);
		free (ohl);
	}

	close (fd);
	free (filename);

	return true;
}

#define TRANSITION 1

R_API bool r_core_project_save(RCore *core, const char *file) {
	bool scr_null = false;
	bool ret = true;
	char *prj, buf[1024];
	SdbListIter *it;
	SdbNs *ns;
	int prjType = 1; // 0=old (file + file.d/) 1=new (file/*)

	if (!file || !*file) {
		return false;
	}
	prj = r_core_project_file (core, file);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", file);
		return false;
	}
	char *prjDir = r_file_dirname (prj);
	if (r_file_exists (prj)) {
		if (r_file_is_directory (prj)) {
			eprintf ("WTF. rc is a directory?\n");
			eprintf ("rm -rf %s.d\n", prj);
		}
#if 0
		if (r_file_is_regular (prj)) {
			prjType = 0;
			prjDir = strdup (prj);
#if TRANSITION
			prjType = 1;
			r_file_rm (prj);
			eprintf ("rm -f %s\n", prj);
			eprintf ("rm -rf %s.d\n", prj);
			char *newPrj = r_str_newf ("%s/rc", prj);
			free (prj);
			prj = newPrj;
			free (prjDir);
			prjDir = r_file_dirname (prj);
#endif
		}
#endif
	} else {
		free (prjDir);
		prjDir = strdup (prj);
		char *newPrj = r_str_newf ("%s/rc", prj);
		free (prj);
		prj = newPrj;
	}
	if (!prjDir) {
		prjDir = strdup (prj);
	}
	switch (prjType) {
	case 0:
		if (r_file_is_directory (prj)) {
			eprintf ("Error: Target cannot be a directory\n");
			free (prj);
			free (prjDir);
			free (prjDir);
			return false;
		}
		break;
	case 1:
		if (!r_file_exists (prj)) {
			r_sys_mkdirp (prjDir);
		}
		break;
	}
	if (r_config_get_i (core->config, "scr.null")) {
		r_config_set_i (core->config, "scr.null", false);
		scr_null = true;
	}
	r_core_project_init (core);

	char *xrefs_path = prjType == 0
		? r_str_newf ("%s.d" R_SYS_DIR "xrefs", prj)
		: r_str_newf ("%s" R_SYS_DIR "xrefs", prjDir);
	r_anal_project_save (core->anal, xrefs_path);
	free (xrefs_path);

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	if (rop_db) {
		ls_foreach (rop_db->ns, it, ns) {
			char *rop_path = prjType == 0
				? r_str_newf ("%s.d" R_SYS_DIR "rop" R_SYS_DIR "%s", prj, ns->name)
				: r_str_newf ("%s" R_SYS_DIR "rop" R_SYS_DIR "%s", prj, ns->name);
			sdb_file (ns->sdb, buf);
			sdb_sync (ns->sdb);
			free (rop_path);
		}
	}
	if (!r_core_project_save_rdb (core, prj, R_CORE_PRJ_ALL ^ R_CORE_PRJ_XREFS)) {
		eprintf ("Cannot open '%s' for writing\n", prj);
		ret = false;
	}

	if (r_config_get_i (core->config, "prj.files")) {
		// TODO: iterate over all opened files
		const char *binFile = r_core_project_info (core, file);
		const char *binFileName = r_file_basename (binFile);
		char *prjBinDir = r_str_newf ("%s/bin", prjDir);
		char *prjBinFile = r_str_newf ("%s/%s", prjBinDir, binFileName);
		r_sys_mkdirp (prjBinDir);
		if (!r_file_copy (binFile, prjBinFile)) {
			eprintf ("Warning: Cannot copy '%s' into '%s'\n", binFile, prjBinFile);
		}
		free (prjBinFile);
	}
	free (prj);
	free (prjDir);
	if (scr_null) {
		r_config_set_i (core->config, "scr.null", true);
	}
	return ret;
}

R_API char *r_core_project_notes_file (RCore *core, const char *file) {
	char *notes_txt;
	const char *prjdir = r_config_get (core->config, "dir.projects");
	char *prjpath = r_file_abspath (prjdir);
	notes_txt = r_str_newf ("%s"R_SYS_DIR"%s.d"R_SYS_DIR"notes.txt", prjpath, file);
	free (prjpath);
	return notes_txt;
}

#define DB core->anal->sdb_xrefs

static bool r_core_project_load_xrefs(RCore *core, const char *prjName) {
	char *path, *db;

	if (!prjName || !*prjName) {
		return false;
	}
	const char *prjdir = r_config_get (core->config, "dir.projects");

	if (prjName[0] == '/') {
		db = r_str_newf ("%s.d", prjName);
		if (!db) {
			return false;
		}
		path = strdup (db);
	} else {
		db = r_str_newf ("%s/%s.d", prjdir, prjName);
		if (!db) return false;
		path = r_file_abspath (db);
	}

	if (!path) {
		free (db);
		return false;
	}

	if (!sdb_ns_unset (core->anal->sdb, NULL, DB)) {
		sdb_free (DB);
	}
	DB = sdb_new (path, "xrefs", 0);
	if (!DB) {
		free (db);
		free (path);
		return false;
	}
	sdb_ns_set (core->anal->sdb, "xrefs", DB);
	free (path);
	free (db);
	return true;
}
