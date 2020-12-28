/* radare - LGPL - Copyright 2010-2020 - pancake, maijin */

#include <r_types.h>
#include <r_list.h>
#include <r_flag.h>
#include <r_core.h>
#define USE_R2 1
#include <spp/spp.h>

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
		if (isalpha(name[i])) {
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
			prjfile = r_str_append (prjfile, R_SYS_DIR "rc");
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
		if (r_str_endswith (path, R_SYS_DIR "rc") && r_file_exists (path)) {
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
		char *notes_txt = r_str_newf ("%s%s%s", pd, R_SYS_DIR, "notes.txt");
		if (r_file_exists (notes_txt)) {
			r_file_rm (notes_txt);
			eprintf ("rm %s\n", notes_txt);
		}
		free(notes_txt);
}

static inline void remove_rop_directory(const char *prj_dir) {
		char *rop_d = r_str_newf ("%s%s%s", prj_dir, R_SYS_DIR, "rop.d");

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
	char *path, *db = NULL, *path_ns;
	bool found = 0;
	SdbListIter *it;
	SdbNs *ns;

	if (!prjfile || !*prjfile) {
		return false;
	}

	Sdb *rop_db = sdb_ns (core->sdb, "rop", false);
	Sdb *nop_db = sdb_ns (rop_db, "nop", false);
	Sdb *mov_db = sdb_ns (rop_db, "mov", false);
	Sdb *const_db = sdb_ns (rop_db, "const", false);
	Sdb *arithm_db = sdb_ns (rop_db, "arithm", false);
	Sdb *arithmct_db = sdb_ns (rop_db, "arithm_ct", false);

	char *rc_path = get_project_script_path (core, prjfile);
	char *prj_dir = r_file_dirname (rc_path);

	if (r_str_endswith (prjfile, R_SYS_DIR "rc")) {
		// XXX
		eprintf ("ENDS WITH\n");
		path = strdup (prjfile);
		path[strlen (path) - 3] = 0;
	} else if (r_file_fexists ("%s%s%src", R_SYS_DIR, prj_dir, prjfile)) {
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

/*** vvv thready ***/

typedef struct {
	RCore *core;
	char *prj_name;
	char *rc_path;
} projectState;

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

/*** ^^^ thready ***/

static ut64 get_project_laddr(RCore *core, const char *prjfile) {
	ut64 laddr = 0;
	char *buf = r_file_slurp (prjfile, NULL);
	char *pos;
	if (buf) {
		if ((pos = strstr(buf, "\"e bin.laddr = "))) {
			laddr = r_num_math (NULL, pos + 15);
		}
		free (buf);
	}
	return laddr;
}

R_API bool r_core_project_open(RCore *core, const char *prjfile, bool thready) {
	bool askuser = true;
	int ret, close_current_session = 1;
	char *oldbin;
	const char *newbin;
	ut64 mapaddr = 0;
	if (!prjfile || !*prjfile) {
		return false;
	}
	if (thready) {
		eprintf ("Loading projects in a thread has been deprecated. Use tasks\n");
		return false;
	}
	char *prj = get_project_script_path (core, prjfile);
	if (!prj) {
		eprintf ("Invalid project name '%s'\n", prjfile);
		return false;
	}
	char *filepath = r_core_project_info (core, prj);
	// eprintf ("OPENING (%s) from %s\n", prj, r_config_get (core->config, "file.path"));
	/* if it is not an URI */
	if (!filepath) {
		eprintf ("Cannot retrieve information for project '%s'\n", prj);
		free (prj);
		return false;
	}

	if (!filepath[0]) {
		goto cookiefactory;
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
 cookiefactory:
	;
	const char *file_path = r_config_get (core->config, "file.path");
	if (!file_path || !*file_path) {
		file_path = r_config_get (core->config, "file.lastpath");
	}
	oldbin = strdup (file_path);
	if (!strcmp (prjfile, r_config_get (core->config, "prj.name"))) {
		// eprintf ("Reloading project\n");
		askuser = false;
#if 0
		free (prj);
		free (filepath);
		return false;
#endif
	}
	if (askuser) {
		if (r_cons_is_interactive ()) {
			close_current_session = r_cons_yesno ('y', "Close current session? (Y/n)");
		}
	}
	if (close_current_session) {
		// delete
		r_core_file_close_fd (core, -1);
		r_io_close_all (core->io);
		r_anal_purge (core->anal);
		r_flag_unset_all (core->flags);
		r_bin_file_delete_all (core->bin);
		// open new file
		// TODO: handle read/read-write mode
		if (filepath[0]) {
			/* Old-style project without embedded on commands to open all files.  */
			if (!r_core_file_open (core, filepath, 0, UT64_MAX)) {
				eprintf ("Cannot open file '%s'\n", filepath);
				ret = false;
				goto beach;
			}
		}
	}
	mapaddr = get_project_laddr (core, prj);
	if (mapaddr) {
		r_config_set_i (core->config, "bin.laddr", mapaddr);
	}
	if (filepath[0] && close_current_session && r_config_get_i (core->config, "file.info")) {
		mapaddr = r_config_get_i (core->config, "file.offset");
		(void)r_core_bin_load (core, filepath, mapaddr? mapaddr: UT64_MAX);
	}
	/* load sdb stuff in here */
	ret = r_core_project_load (core, prjfile, prj);
	if (filepath[0]) {
		newbin = r_config_get (core->config, "file.path");
		if (!newbin || !*newbin) {
			newbin = r_config_get (core->config, "file.lastpath");
		}
		if (strcmp (oldbin, newbin)) {
			eprintf ("WARNING: file.path changed: %s => %s\n", oldbin, newbin);
		}
	}
beach:
	free (oldbin);
	free (filepath);
	free (prj);
	return ret;
}

R_API char *r_core_project_info(RCore *core, const char *prjfile) {
	FILE *fd;
	char buf[256], *file = NULL;
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
			if (!strncmp (buf, "\"e file.path = ", 15)) {
				buf[strlen (buf) - 2] = 0;
				file = r_str_new (buf + 15);
				break;
			}
			if (!strncmp (buf, "\"e file.lastpath = ", 19)) {
				buf[strlen (buf) - 2] = 0;
				file = r_str_new (buf + 19);
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

static int fdc;		//this is a ugly, remove it, when we have $fd

static bool store_files_and_maps (RCore *core, RIODesc *desc, ut32 id) {
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

static bool simple_project_save_script(RCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold;

	if (!file || * file == '\0') {
		return false;
	}

	filename = r_str_word_get_first (file);
	fd = r_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
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
	r_cons_singleton ()->context->is_interactive = false; // NOES must use api

	r_str_write (fd, "# r2 rdb project file\n");

	if (opts & R_CORE_PRJ_EVAL) {
		r_str_write (fd, "# eval\n");
		r_config_list (core->config, NULL, true);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_FCNS) {
		r_str_write (fd, "# functions\n");
		r_str_write (fd, "fs functions\n");
		r_core_cmd (core, "afl*", 0);
		r_cons_flush ();
	}

	if (opts & R_CORE_PRJ_FLAGS) {
		r_str_write (fd, "# flags\n");
		r_core_cmd (core, "f.**", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_META) {
		r_str_write (fd, "# meta\n");
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 1);
		r_cons_flush ();
		r_core_cmd (core, "fV*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_XREFS) {
		r_str_write (fd, "# xrefs\n");
		r_core_cmd (core, "ax*", 0);
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

static bool project_save_script(RCore *core, const char *file, int opts) {
	char *filename, *hl, *ohl = NULL;
	int fd, fdold;

	if (!file || *file == '\0') {
		return false;
	}

	filename = r_str_word_get_first (file);
	fd = r_sandbox_open (file, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, 0644);
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
	if (!core->bin->is_debugger && !r_config_get_i (core->config, "asm.emu")) {
		if (core->bin->file) {
			char *fpath = r_file_abspath (core->bin->file);
			if (fpath) {
				char *reopen = r_str_newf ("\"o %s\"\n", fpath);
				if (reopen) {
					r_str_write (fd, reopen);
					free (reopen);
					free (fpath);
				}
			}
		}
	}
	// Set file.path and file.lastpath to empty string to signal
	// new behaviour to project load routine (see io maps below).
	r_config_set (core->config, "file.path", "");
	r_config_set (core->config, "file.lastpath", "");
	if (opts & R_CORE_PRJ_EVAL) {
		r_str_write (fd, "# eval\n");
		r_config_list (core->config, NULL, true);
		r_cons_flush ();
	}

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
	if (opts & R_CORE_PRJ_IO_MAPS && core->io && core->io->files) {
		fdc = 3;
		r_id_storage_foreach (core->io->files, (RIDStorageForeachCb)store_files_and_maps, core);
		r_cons_flush ();
	}
	{
		r_core_cmd (core, "fz*", 0);
		r_cons_flush ();
	}
	if (opts & R_CORE_PRJ_META) {
		r_str_write (fd, "# meta\n");
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 1);
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

#define TRANSITION 1

R_API bool r_core_project_save(RCore *core, const char *prj_name) {
	bool scr_null = false;
	bool ret = true;
	char *script_path, *prj_dir;
	SdbListIter *it;
	SdbNs *ns;
	char *old_prj_name = NULL;
	r_return_val_if_fail(prj_name && *prj_name, false);
	script_path = get_project_script_path (core, prj_name);
	if (!script_path) {
		eprintf ("Invalid project name '%s'\n", prj_name);
		return false;
	}
	if (r_str_endswith (script_path, R_SYS_DIR "rc")) {
		/* new project format */
		prj_dir = r_file_dirname (script_path);
	} else {
		prj_dir = r_str_newf ("%s.d", script_path);
	}
	if (r_file_exists (script_path)) {
		if (r_file_is_directory (script_path)) {
			eprintf ("WTF. rc is a directory?\n");
		}
		if (r_str_endswith (prj_dir, ".d")) {
			eprintf ("Upgrading project...\n");
#if TRANSITION
			r_file_rm (script_path);
			r_sys_mkdirp (prj_dir);
			eprintf ("Please remove: rm -rf %s %s.d\n", prj_name, prj_name);
			char *rc = r_str_newf ("%s" R_SYS_DIR "rc", prj_dir);
			if (!rc) {
				free (prj_dir);
				free (script_path);
				return false;
			}
			free (script_path);
			script_path = rc;
			free (prj_dir);
			prj_dir = r_file_dirname (script_path);
#endif
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

	const char *old_prj_name_conf = r_config_get (core->config, "prj.name");
	if (old_prj_name_conf) {
		old_prj_name = strdup (old_prj_name_conf);
	}
	r_config_set (core->config, "prj.name", prj_name);
	if (r_config_get_i (core->config, "prj.simple")) {
		if (!simple_project_save_script (core, script_path, R_CORE_PRJ_ALL)) {
			eprintf ("Cannot open '%s' for writing\n", prj_name);
			ret = false;
		}
	} else {
		if (!project_save_script (core, script_path, R_CORE_PRJ_ALL)) {
			eprintf ("Cannot open '%s' for writing\n", prj_name);
			ret = false;
		}
	}

	if (r_config_get_i (core->config, "prj.files")) {
		eprintf ("TODO: prj.files: support copying more than one file into the project directory\n");
		char *bin_file = r_core_project_info (core, prj_name);
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
			r_sys_cmd ("git add * ; git commit -a");
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
	if (!ret && old_prj_name) {
		// reset prj.name on fail
		r_config_set (core->config, "prj.name", old_prj_name);
	}
	free (script_path);
	free (old_prj_name);
	return ret;
}

R_API char *r_core_project_notes_file(RCore *core, const char *prj_name) {
	char *notes_txt;
	const char *prjdir = r_config_get (core->config, "dir.projects");
	char *prjpath = r_file_abspath (prjdir);
	notes_txt = r_str_newf ("%s"R_SYS_DIR "%s"R_SYS_DIR "notes.txt", prjpath, prj_name);
	free (prjpath);
	return notes_txt;
}

R_API bool r_core_project_load(RCore *core, const char *prj_name, const char *rcpath) {
	const bool cfg_fortunes = r_config_get_i (core->config, "cfg.fortunes");
	const bool scr_interactive = r_cons_is_interactive ();
	const bool scr_prompt = r_config_get_i (core->config, "scr.prompt");
	(void) load_project_rop (core, prj_name);
	bool ret = r_core_cmd_file (core, rcpath);
	r_config_set_i (core->config, "cfg.fortunes", cfg_fortunes);
	r_config_set_i (core->config, "scr.interactive", scr_interactive);
	r_config_set_i (core->config, "scr.prompt", scr_prompt);
	r_config_bump (core->config, "asm.arch");
	return ret;
}
