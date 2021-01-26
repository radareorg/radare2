/* radare - LGPL - Copyright 2010-2020 - pancake, maijin */

#include <r_types.h>
#include <r_list.h>
#include <r_flag.h>
#include <r_core.h>
#define USE_R2 1
#include <spp/spp.h>

#define PROJECT_EXPERIMENTAL 0

// project apis to be used from cmd_project.c

static bool is_valid_project_name(const char *name) {
	int i;
	if (r_str_endswith (name, ".zip")) {
		return false;
	}
	for (i = 0; name[i]; i++) {
		switch (name[i]) {
		case '\\': // for w32
		case '.':
		case '_':
		case ':':
		case '-':
			continue;
		}
		if (isalpha ((unsigned char)name[i])) {
			continue;
		}
		if (IS_DIGIT (name[i])) {
			continue;
		}
		return false;
	}
	return true;
}

static char *get_project_script_path(RCore *core, const char *file) {
	r_return_val_if_fail (core && !R_STR_ISEMPTY (file), NULL);
	const char *magic = "# r2 rdb project file";
	char *data, *prjfile;
	if (r_file_is_abspath (file)) {
		prjfile = strdup (file);
	} else {
		if (!is_valid_project_name (file)) {
			return NULL;
		}
		prjfile = r_file_abspath (r_config_get (core->config, "dir.projects"));
		prjfile = r_str_append (prjfile, R_SYS_DIR);
		prjfile = r_str_append (prjfile, file);
		if (!r_file_exists (prjfile) || r_file_is_directory (prjfile)) {
			prjfile = r_str_append (prjfile, R_SYS_DIR "rc.r2");
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

static int make_projects_directory(RCore *core) {
	char *prjdir = r_file_abspath (r_config_get (core->config, "dir.projects"));
	int ret = r_sys_mkdirp (prjdir);
	if (!ret) {
		eprintf ("Cannot mkdir dir.projects\n");
	}
	free (prjdir);
	return ret;
}

R_API bool r_core_is_project(RCore *core, const char *name) {
	bool ret = false;
	if (name && *name && *name != '.') {
		char *path = get_project_script_path (core, name);
		if (!path) {
			return false;
		}
		if (r_str_endswith (path, R_SYS_DIR "rc.r2") && r_file_exists (path)) {
			ret = true;
		} else {
			path = r_str_append (path, ".d");
			if (r_file_is_directory (path)) {
				ret = true;
			}
		}
		free (path);
	}
	return ret;
}

R_API int r_core_project_cat(RCore *core, const char *name) {
	char *path = get_project_script_path (core, name);
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
	PJ *pj = NULL;
	RListIter *iter;
	RList *list;

	char *foo, *path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	if (!path) {
		return 0;
	}
	list = r_sys_dir (path);
	switch (mode) {
	case 'j':
		pj = pj_new ();
		if (!pj) {
			break;
		}
		pj_a (pj);
		r_list_foreach (list, iter, foo) {
			// todo. escape string
			if (r_core_is_project (core, foo)) {
				pj_s (pj, foo);
			}
		}
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
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

static inline void remove_project_file(char * path) {
	if (r_file_exists (path)) {
		r_file_rm (path);
		eprintf ("rm %s\n", path);
	}
}

static inline void remove_notes_file(const char *pd) {
	char *notes_txt = r_file_new (pd, "notes.txt", NULL);
	if (r_file_exists (notes_txt)) {
		r_file_rm (notes_txt);
		eprintf ("rm %s\n", notes_txt);
	}
	free (notes_txt);
}

static inline void remove_rop_directory(const char *prj_dir) {
	char *rop_d = r_file_new (prj_dir, "rop.d", NULL);

	if (r_file_is_directory (rop_d)) {
		char *f;
		RListIter *iter;
		RList *files = r_sys_dir (rop_d);
		r_list_foreach (files, iter, f) {
			char *filepath = r_str_append (strdup (rop_d), R_SYS_DIR);
			filepath = r_str_append (filepath, f);
			if (!r_file_is_directory (filepath)) {
				eprintf ("rm %s\n", filepath);
				r_file_rm (filepath);
			}

			free (filepath);
		}
		r_file_rm (rop_d);
		eprintf ("rm %s\n", rop_d);
		r_list_free (files);
	}

	free (rop_d);
}
R_API int r_core_project_delete(RCore *core, const char *prjfile) {
	if (r_sandbox_enable (0)) {
		eprintf ("Cannot delete project in sandbox mode\n");
		return 0;
	}
	char *path = get_project_script_path (core, prjfile);
	if (!path) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	if (r_core_is_project (core, prjfile)) {
		char *prj_dir = r_file_dirname (path);
		if (!prj_dir) {
			eprintf ("Cannot resolve directory\n");
			free (path);
			return false;
		}
		remove_project_file (path);
		remove_notes_file (prj_dir);
		remove_rop_directory (prj_dir);
		// remove directory only if it's empty
		r_file_rm (prj_dir);
		free (prj_dir);
	}
	free (path);
	return 0;
}

static bool load_project_rop(RCore *core, const char *prjfile) {
	r_return_val_if_fail (core && !R_STR_ISEMPTY (prjfile), false);
	char *path, *db = NULL, *path_ns;
	bool found = 0;
	SdbListIter *it;
	SdbNs *ns;

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	Sdb *nop_db = sdb_ns (rop_db, "nop", false);
	Sdb *mov_db = sdb_ns (rop_db, "mov", false);
	Sdb *const_db = sdb_ns (rop_db, "const", false);
	Sdb *arithm_db = sdb_ns (rop_db, "arithm", false);
	Sdb *arithmct_db = sdb_ns (rop_db, "arithm_ct", false);

	char *rc_path = get_project_script_path (core, prjfile);
	char *prj_dir = r_file_dirname (rc_path);

	if (r_str_endswith (prjfile, R_SYS_DIR "rc.r2")) {
		// XXX
		eprintf ("ENDS WITH\n");
		path = strdup (prjfile);
		path[strlen (path) - 3] = 0;
	} else if (r_file_fexists ("%s%s%src.r2", R_SYS_DIR, prj_dir, prjfile)) {
		path = r_str_newf ("%s%s%s", R_SYS_DIR, prj_dir, prjfile);
	} else {
		if (*prjfile == R_SYS_DIR[0]) {
			db = r_str_newf ("%s.d", prjfile);
			if (!db) {
				free (prj_dir);
				free (rc_path);
				return false;
			}
			path = strdup (db);
		} else {
			db = r_str_newf ("%s" R_SYS_DIR "%s.d", prj_dir, prjfile);
			if (!db) {
				free (prj_dir);
				free (rc_path);
				return false;
			}
			path = r_file_abspath (db);
		}
	}
	if (!path) {
		free (db);
		free (prj_dir);
		free (rc_path);
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
		free (prj_dir);
		free (rc_path);
		return false;
	}
	sdb_ns_set (core->sdb, "rop", rop_db);

	path_ns = r_str_newf ("%s" R_SYS_DIR "rop", prj_dir);
	if (!r_file_exists (path_ns)) {
		path_ns = r_str_append (path_ns, ".sdb");
	}
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
	free (prj_dir);
	free (rc_path);
	return true;
}

R_API void r_core_project_execute_cmds(RCore *core, const char *prjfile) {
	char *str = r_core_project_notes_file (core, prjfile);
	char *data = r_file_slurp (str, NULL);
	if (!data) {
		free (str);
		return;
	}
	Output out;
	out.fout = NULL;
	out.cout = r_strbuf_new (NULL);
	r_strbuf_init (out.cout);
	struct Proc proc;
	spp_proc_set (&proc, "spp", 1);
	spp_eval (data, &out);
	free (data);
	data = strdup (r_strbuf_get (out.cout));
	char *bol = strtok (data, "\n");
	while (bol) {
		if (bol[0] == ':') {
			r_core_cmd0 (core, bol + 1);
		}
		bol = strtok (NULL, "\n");
	}
	free (data);
	free (str);
}

typedef struct {
	RCore *core;
	char *prj_name;
	char *rc_path;
} projectState;

static bool r_core_project_load(RCore *core, const char *prj_name, const char *rcpath) {
	if (R_STR_ISEMPTY (prj_name)) {
		prj_name = r_core_project_name (core, rcpath);
	}
	if (r_project_is_loaded (core->prj)) {
		eprintf ("o--;e prj.name=\n");
		return false;
	}
	if (!r_project_open (core->prj, prj_name, rcpath)) {
		return false;
	}
	const bool cfg_fortunes = r_config_get_i (core->config, "cfg.fortunes");
	const bool scr_interactive = r_cons_is_interactive ();
	const bool scr_prompt = r_config_get_i (core->config, "scr.prompt");
	(void) load_project_rop (core, prj_name);
	bool ret = r_core_cmd_file (core, rcpath);
	r_config_set_i (core->config, "cfg.fortunes", cfg_fortunes);
	r_config_set_i (core->config, "scr.interactive", scr_interactive);
	r_config_set_i (core->config, "scr.prompt", scr_prompt);
	r_config_bump (core->config, "asm.arch");
	r_config_set (core->config, "prj.name", prj_name);
	return ret;
}

static RThreadFunctionRet project_load_background(RThread *th) {
	projectState *ps = th->user;
	r_core_project_load (ps->core, ps->prj_name, ps->rc_path);
	free (ps->prj_name);
	free (ps->rc_path);
	free (ps);
	return R_TH_STOP;
}

R_API RThread *r_core_project_load_bg(RCore *core, const char *prj_name, const char *rc_path) {
	projectState *ps = R_NEW0 (projectState);
	ps->core = core;
	ps->prj_name = strdup (prj_name);
	ps->rc_path = strdup (rc_path);
	RThread *th = r_th_new (project_load_background, ps, false);
	if (th) {
		r_th_start (th, true);
		char thname[32] = {0};
		size_t thlen = R_MIN (strlen (prj_name), sizeof (thname) - 1);
		r_str_ncpy (thname, prj_name, thlen);
		r_th_setname (th, thname);
	}
	return th;
}

R_API bool r_core_project_open(RCore *core, const char *prj_path) {
	r_return_val_if_fail (core && !R_STR_ISEMPTY (prj_path), false);
	int ret, close_current_session = 1;
	if (r_project_is_loaded (core->prj)) {
		eprintf ("There's a project already opened\n");
		bool ccs = r_cons_yesno ('y', "Close current session? (Y/n)");
		if (ccs) {
			r_core_cmd0 (core, "o--");
		} else {
			eprintf ("Project not loaded.\n");
			return false;
		}
	}
	char *prj_name = r_core_project_name (core, prj_path);
	char *prj_script = get_project_script_path (core, prj_path);
	if (!prj_script) {
		eprintf ("Invalid project name '%s'\n", prj_path);
		return false;
	}
	if (r_project_is_loaded (core->prj)) {
		if (r_cons_is_interactive ()) {
			close_current_session = r_cons_yesno ('y', "Close current session? (Y/n)");
		}
	}
	if (close_current_session) {
		r_core_cmd0 (core, "e prj.name=;o--");
	}
	/* load sdb stuff in here */
	ret = r_core_project_load (core, prj_name, prj_script);
	free (prj_name);
	free (prj_script);
	return ret;
}

R_API char *r_core_project_name(RCore *core, const char *prjfile) {
	FILE *fd;
	char buf[256], *file = NULL;
	if (*prjfile != '/') {
		return strdup (prjfile);
	}
	char *prj = get_project_script_path (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return NULL;
	}
	fd = r_sandbox_fopen (prj, "r");
	if (fd) {
		for (;;) {
			if (!fgets (buf, sizeof (buf), fd)) {
				break;
			}
			if (feof (fd)) {
				break;
			}
			if (!strncmp (buf, "\"e prj.name = ", 14)) {
				buf[strlen (buf) - 2] = 0;
				file = r_str_new (buf + 14);
				break;
			}
		}
		fclose (fd);
	} else {
		eprintf ("Cannot open project info (%s)\n", prj);
	}
	free (prj);
	if (R_STR_ISEMPTY (file)) {
		free (file);
		file = strdup (prjfile);
		char *slash = (char *)r_str_lchr (file, R_SYS_DIR[0]); 
		if (slash) {
			*slash = 0;
			slash = (char *)r_str_lchr (file, R_SYS_DIR[0]); 
			if (slash) {
				char *res = strdup (slash + 1);
				free (file);
				file = res;
			} else {
				R_FREE (file);
			}
		} else {
			R_FREE (file);
		}
	}
	return file;
}

#if PROJECT_EXPERIMENTAL
static int fdc; // TODO: move into a struct passed to the foreach instead of global

static bool store_files_and_maps(RCore *core, RIODesc *desc, ut32 id) {
	RList *maps = NULL;
	RListIter *iter;
	RIOMap *map;
	if (desc) {
		// reload bin info
		r_cons_printf ("\"obf %s\"\n", desc->uri);
		r_cons_printf ("\"ofs \\\"%s\\\" %s\"\n", desc->uri, r_str_rwx_i (desc->perm));
		if ((maps = r_io_map_get_for_fd (core->io, id))) {
			r_list_foreach (maps, iter, map) {
				r_cons_printf ("om %d 0x%"PFMT64x" 0x%"PFMT64x" 0x%"PFMT64x" %s%s%s\n", fdc,
					r_io_map_begin (map), r_io_map_size (map), map->delta, r_str_rwx_i (map->perm),
					map->name ? " " : "", r_str_get (map->name));
			}
			r_list_free (maps);
		}
		fdc++;
	}
	return true;
}
#endif

static bool project_save_script(RCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fdold;

	if (R_STR_ISEMPTY (file)) {
		return false;
	}

	filename = r_str_word_get_first (file);
	int fd = r_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
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
	r_cons_singleton ()->context->is_interactive = false;
	r_str_write (fd, "# r2 rdb project file\n");
	// new behaviour to project load routine (see io maps below).
	if (opts & R_CORE_PRJ_EVAL) {
		r_str_write (fd, "# eval\n");
		r_config_list (core->config, NULL, true);
		r_cons_flush ();
	}
	r_core_cmd (core, "o*", 0);
	r_core_cmd0 (core, "tcc*");
	if (opts & R_CORE_PRJ_FCNS) {
		r_str_write (fd, "# functions\n");
		r_str_write (fd, "fs functions\n");
		r_core_cmd (core, "afl*", 0);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_FLAGS) {
		r_str_write (fd, "# flags\n");
		r_flag_space_push (core->flags, NULL);
		r_flag_list (core->flags, true, NULL);
		r_flag_space_pop (core->flags);
		r_cons_flush ();
	}
#if PROJECT_EXPERIMENTAL
	if (opts & R_CORE_PRJ_IO_MAPS && core->io && core->io->files) {
		fdc = 3;
		r_id_storage_foreach (core->io->files, (RIDStorageForeachCb)store_files_and_maps, core);
		r_cons_flush ();
	}
#endif
	{
		r_core_cmd (core, "fz*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_META) {
		r_str_write (fd, "# meta\n");
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 1, NULL);
		r_cons_flush ();
		r_core_cmd (core, "fV*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_XREFS) {
		r_core_cmd (core, "ax*", 0);
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
		r_str_write (fd, "# aliases\n");
		r_core_cmd (core, "$*", 0);
		r_cons_flush ();
	}
	r_core_cmd (core, "wc*", 0);
	if (opts & R_CORE_PRJ_ANAL_SEEK) {
		r_cons_printf ("# seek\n"
			"s 0x%08"PFMT64x "\n", core->offset);
		r_cons_flush ();
	}

	r_cons_singleton ()->fdout = fdold;
	r_cons_singleton ()->context->is_interactive = true;

	if (ohl) {
		r_cons_highlight (ohl);
		free (ohl);
	}

	close (fd);
	free (filename);

	return true;
}

R_API bool r_core_project_save_script(RCore *core, const char *file, int opts) {
	return project_save_script (core, file, opts);
}

R_API bool r_core_project_save(RCore *core, const char *prj_name) {
	bool scr_null = false;
	bool ret = true;
	SdbListIter *it;
	SdbNs *ns;
	r_return_val_if_fail (prj_name && *prj_name, false);
	char *script_path = get_project_script_path (core, prj_name);
	if (r_config_get_i (core->config, "cfg.debug")) {
		eprintf ("radare2 does not support projects on debugged bins.\n");
		return false;
	}
	if (!script_path) {
		eprintf ("Invalid project name '%s'\n", prj_name);
		return false;
	}
	char *prj_dir = NULL;
	if (r_str_endswith (script_path, R_SYS_DIR "rc.r2")) {
		/* new project format */
		prj_dir = r_file_dirname (script_path);
	} else {
		prj_dir = r_str_newf ("%s.d", script_path);
	}
	if (r_file_exists (script_path)) {
		if (r_file_is_directory (script_path)) {
			eprintf ("Structural error: rc.r2 shouldnt be a directory.\n");
		}
	}
	if (!prj_dir) {
		prj_dir = strdup (prj_name);
	}
	if (!r_file_exists (prj_dir)) {
		r_sys_mkdirp (prj_dir);
	}
	if (r_config_get_i (core->config, "scr.null")) {
		r_config_set_i (core->config, "scr.null", false);
		scr_null = true;
	}
	make_projects_directory (core);

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	if (rop_db) {
		/* set filepath for all the rop sub-dbs */
		ls_foreach (rop_db->ns, it, ns) {
			char *rop_path = r_str_newf ("%s" R_SYS_DIR "rop.d" R_SYS_DIR "%s", prj_dir, ns->name);
			sdb_file (ns->sdb, rop_path);
			sdb_sync (ns->sdb);
			free (rop_path);
		}
	}

	if (!project_save_script (core, script_path, R_CORE_PRJ_ALL)) {
		eprintf ("Cannot open '%s' for writing\n", prj_name);
		ret = false;
	}

	if (r_config_get_i (core->config, "prj.files")) {
		eprintf ("TODO: prj.files: support copying more than one file into the project directory\n");
		char *bin_file = r_core_project_name (core, prj_name);
		const char *bin_filename = r_file_basename (bin_file);
		char *prj_bin_dir = r_str_newf ("%s" R_SYS_DIR "bin", prj_dir);
		char *prj_bin_file = r_str_newf ("%s" R_SYS_DIR "%s", prj_bin_dir, bin_filename);
		r_sys_mkdirp (prj_bin_dir);
		if (!r_file_copy (bin_file, prj_bin_file)) {
			eprintf ("Warning: Cannot copy '%s' into '%s'\n", bin_file, prj_bin_file);
		}
		free (prj_bin_file);
		free (prj_bin_dir);
		free (bin_file);
	}
	if (r_config_get_i (core->config, "prj.git")) {
		char *cwd = r_sys_getdir ();
		char *git_dir = r_str_newf ("%s" R_SYS_DIR ".git", prj_dir);
		if (r_sys_chdir (prj_dir)) {
			if (!r_file_is_directory (git_dir)) {
				r_sys_cmd ("git init");
			}
			if (r_cons_is_interactive ()) {
				r_sys_cmd ("git add * ; git commit -a");
			} else {
				r_sys_cmd ("git add * ; git commit -a -m commit");
			}
		} else {
			eprintf ("Cannot chdir %s\n", prj_dir);
		}
		r_sys_chdir (cwd);
		free (git_dir);
		free (cwd);
	}
	if (r_config_get_i (core->config, "prj.zip")) {
		char *cwd = r_sys_getdir ();
		const char *prj_name = r_file_basename (prj_dir);
		if (r_sys_chdir (prj_dir)) {
			if (!strchr (prj_name, '\'')) {
				r_sys_chdir ("..");
				r_sys_cmdf ("rm -f '%s.zip'; zip -r '%s'.zip '%s'",
					prj_name, prj_name, prj_name);
			} else {
				eprintf ("Command injection attempt?\n");
			}
		} else {
			eprintf ("Cannot chdir %s\n", prj_dir);
		}
		r_sys_chdir (cwd);
		free (cwd);
	}
	// LEAK : not always in heap free (prj_name);
	free (prj_dir);
	if (scr_null) {
		r_config_set_i (core->config, "scr.null", true);
	}
	free (script_path);
	r_config_set (core->config, "prj.name", prj_name);
	return ret;
}

R_API char *r_core_project_notes_file(RCore *core, const char *prj_name) {
	const char *prjdir = r_config_get (core->config, "dir.projects");
	char *prjpath = r_file_abspath (prjdir);
	char *notes_txt = r_file_new (prjpath, prj_name, "notes.txt", NULL);
	free (prjpath);
	return notes_txt;
}
